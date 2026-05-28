"""Image Builder for Firecracker MicroVM guest images.

Responsible for:
- Downloading a pre-compiled Firecracker-compatible Linux kernel
- Building a minimal ext4 rootfs containing Python, pytest, security
  scanners (bandit, safety), and the guest agent
- Network-silent by design: curl and wget are removed from the image
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class ImageBuilder:
    """Builds Firecracker guest images (kernel + rootfs)."""

    def __init__(self, output_dir: str = "/tmp/firecracker_images") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.kernel_path = self.output_dir / "vmlinux.bin"
        self.rootfs_path = self.output_dir / "rootfs.ext4"

    def build_all(self) -> None:
        """Download kernel and build the rootfs."""
        self.download_kernel()
        self.build_rootfs()

    def download_kernel(self) -> None:
        """Download a pre-compiled Firecracker-compatible kernel."""
        if self.kernel_path.exists():
            logger.info("Kernel already exists at %s", self.kernel_path)
            return

        logger.info("Downloading Firecracker kernel...")
        kernel_url = (
            "https://s3.amazonaws.com/spec.ccfc.min/img/"
            "quickstart_guide/x86_64/kernels/vmlinux.bin"
        )
        subprocess.run(
            ["curl", "-L", "-o", str(self.kernel_path), kernel_url],
            check=True,
        )
        logger.info("Kernel downloaded to %s", self.kernel_path)

    def build_rootfs(self) -> None:
        """Build a minimal ext4 rootfs with Python, pytest, and security tools.

        The rootfs is network-silent by design: no curl, wget, or DNS
        resolution utilities are included. All dependencies must be
        pre-baked into the image.
        """
        if self.rootfs_path.exists():
            logger.info("Rootfs already exists at %s", self.rootfs_path)
            return

        logger.info("Building guest rootfs...")

        # Dockerfile for the guest base image
        dockerfile_content = """\
FROM python:3.11-slim

# Install build dependencies and security tools
RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
        git \\
    && pip install --no-cache-dir \\
        pytest \\
        bandit \\
        safety \\
    && apt-get purge -y curl wget \\
    && apt-get autoremove -y \\
    && rm -rf /var/lib/apt/lists/*

# Create workspace directory
RUN mkdir -p /workspace

# Copy guest agent
COPY guest_agent.py /usr/local/bin/guest_agent.py

# Setup init to start the vsock agent
RUN printf '#!/bin/sh\\n\\
mount -t proc proc /proc\\n\\
mount -t sysfs sysfs /sys\\n\\
mount -t devtmpfs devtmpfs /dev\\n\\
\\n\\
python3 /usr/local/bin/guest_agent.py &\\n\\
\\n\\
# Wait for agent to exit\\n\\
wait\\n\\
poweroff -f\\n' > /sbin/init && chmod +x /sbin/init
"""
        build_context = self.output_dir / "build_context"
        build_context.mkdir(exist_ok=True)

        (build_context / "Dockerfile").write_text(dockerfile_content)

        # Copy guest_agent.py into build context
        current_dir = Path(__file__).parent
        guest_agent_src = current_dir / "guest_agent.py"
        (build_context / "guest_agent.py").write_text(
            guest_agent_src.read_text()
        )

        # Build Docker image
        logger.info("Building Docker image sentinel-guest-base...")
        subprocess.run(
            ["docker", "build", "-t", "sentinel-guest-base", str(build_context)],
            check=True,
        )

        # Create ext4 rootfs from Docker image
        logger.info("Exporting Docker image to ext4 rootfs...")

        # Create empty ext4 filesystem (1GB)
        subprocess.run(
            [
                "dd", "if=/dev/zero",
                f"of={self.rootfs_path}",
                "bs=1M", "count=1024",
            ],
            check=True,
        )
        subprocess.run(["mkfs.ext4", str(self.rootfs_path)], check=True)

        # Mount and populate from Docker image
        subprocess.run(
            [
                "docker", "run", "--rm", "--privileged",
                "-v", f"{self.output_dir}:/output",
                "sentinel-guest-base",
                "sh", "-c",
                (
                    "mkdir -p /mnt/rootfs && "
                    "mount /output/rootfs.ext4 /mnt/rootfs && "
                    "cp -a /bin /etc /lib /root /sbin /usr /var /workspace "
                    "/mnt/rootfs/ 2>/dev/null; "
                    "cp -a /lib64 /mnt/rootfs/ 2>/dev/null; "
                    "mkdir -p /mnt/rootfs/proc /mnt/rootfs/sys /mnt/rootfs/dev "
                    "/mnt/rootfs/tmp && "
                    "umount /mnt/rootfs"
                ),
            ],
            check=True,
        )

        logger.info("Rootfs built at %s", self.rootfs_path)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    builder = ImageBuilder()
    builder.build_all()
    print(f"Images ready at {builder.output_dir}")
