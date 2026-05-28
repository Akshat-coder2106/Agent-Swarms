"""Pool Manager for warm Firecracker MicroVMs.

Maintains a pool of pre-booted (or snapshot-forked) MicroVMs to reduce
startup latency. Supports both snapshot-based forking (sub-100ms) and
fresh cold boots as fallback.
"""

from __future__ import annotations

import logging
import queue
import threading
import uuid
from typing import Optional

from .vm_manager import VMConfig, VMManager, SnapshotManager

logger = logging.getLogger(__name__)


class PoolManager:
    """Manages a warm pool of Firecracker MicroVM instances.

    If a ``SnapshotManager`` is provided and a golden snapshot exists,
    new VMs are forked from the snapshot (fast path). Otherwise, VMs
    are cold-booted from scratch.
    """

    def __init__(
        self,
        pool_size: int = 1,
        config: Optional[VMConfig] = None,
        snapshot_manager: Optional[SnapshotManager] = None,
    ) -> None:
        self.pool_size = pool_size
        self.config = config or VMConfig()
        self._snapshot_mgr = snapshot_manager
        self._pool: queue.Queue[VMManager] = queue.Queue(maxsize=pool_size)
        self._lock = threading.Lock()
        self._fork_counter = 0

    def initialize_pool(self) -> None:
        """Pre-warm the pool with ready-to-use VMs.

        If a golden snapshot is available, forks from it for fast startup.
        Otherwise falls back to cold boots.
        """
        logger.info("Initializing VM pool (size=%d)", self.pool_size)
        for _ in range(self.pool_size):
            self._replenish()

    def _replenish(self) -> None:
        """Boot or fork a new VM and add it to the pool in a background thread."""
        def _boot() -> None:
            try:
                vm = self._create_vm()
                self._pool.put(vm)
                logger.debug("Pool replenished with VM %s", vm.vm_id)
            except Exception:
                logger.exception("Failed to replenish VM pool")

        thread = threading.Thread(target=_boot, daemon=True)
        thread.start()

    def _create_vm(self) -> VMManager:
        """Create a new VM — either from snapshot or via cold boot."""
        with self._lock:
            self._fork_counter += 1
            fork_id = f"{self._fork_counter:04d}-{uuid.uuid4().hex[:6]}"

        # Try snapshot fork first (fast path)
        if self._snapshot_mgr and self._snapshot_mgr.has_golden_snapshot():
            snapshot = self._snapshot_mgr.golden_snapshot
            return self._snapshot_mgr.fork_from_snapshot(snapshot, fork_id)

        # Cold boot fallback
        vm_id = f"pool-vm-{fork_id}"
        vm = VMManager(vm_id=vm_id, config=self.config)
        vm.initialize(from_snapshot=False)
        return vm

    def acquire(self) -> VMManager:
        """Retrieve a warm VM from the pool, or create one on-demand.

        Returns a ``VMManager`` instance ready for command execution.
        The caller must call ``release()`` when done.
        """
        try:
            vm = self._pool.get(block=False)
            logger.debug("Acquired pooled VM %s", vm.vm_id)
            return vm
        except queue.Empty:
            logger.info("Pool empty — creating on-demand VM")
            return self._create_vm()

    def release(self, vm: VMManager) -> None:
        """Destroy a used VM and replenish the pool.

        VMs are destroyed (not reused) after each task to maintain
        a pristine, reproducible state for the next validation.
        """
        vm.destroy()
        with self._lock:
            if self._pool.qsize() < self.pool_size:
                self._replenish()

    def shutdown(self) -> None:
        """Destroy all VMs in the pool. Golden snapshot is preserved."""
        destroyed = 0
        while not self._pool.empty():
            try:
                vm = self._pool.get_nowait()
                vm.destroy()
                destroyed += 1
            except queue.Empty:
                break
        logger.info("Pool shutdown: destroyed %d VMs", destroyed)
