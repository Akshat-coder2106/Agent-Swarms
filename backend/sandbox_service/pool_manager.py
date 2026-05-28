"""
Pool Manager for warm Firecracker MicroVMs.

Maintains a pool of pre-booted MicroVMs to reduce startup latency.
"""
import queue
import threading
import uuid

from .vm_manager import VMConfig, VMManager


class PoolManager:
    def __init__(self, pool_size: int = 3, config: VMConfig | None = None):
        self.pool_size = pool_size
        self.config = config or VMConfig()
        self.pool: queue.Queue[VMManager] = queue.Queue(maxsize=pool_size)
        self.lock = threading.Lock()
        
    def initialize_pool(self):
        """Pre-warms the MicroVM pool."""
        for _ in range(self.pool_size):
            self._replenish()

    def _replenish(self):
        """Starts a new MicroVM and adds it to the pool in the background."""
        def boot():
            vm_id = f"pool-vm-{uuid.uuid4().hex[:8]}"
            vm = VMManager(vm_id=vm_id, config=self.config)
            vm.initialize()
            self.pool.put(vm)
            
        thread = threading.Thread(target=boot, daemon=True)
        thread.start()

    def acquire(self) -> VMManager:
        """Retrieves a warm VM from the pool, or boots one if empty."""
        try:
            return self.pool.get(block=False)
        except queue.Empty:
            # Fallback if pool is empty
            vm_id = f"ondemand-vm-{uuid.uuid4().hex[:8]}"
            vm = VMManager(vm_id=vm_id, config=self.config)
            vm.initialize()
            return vm

    def release(self, vm: VMManager):
        """Destroys the VM after use (to maintain pristine state) and replenishes the pool."""
        vm.destroy()
        with self.lock:
            if self.pool.qsize() < self.pool_size:
                self._replenish()

    def shutdown(self):
        """Cleans up all VMs in the pool."""
        while not self.pool.empty():
            vm = self.pool.get()
            vm.destroy()
