"""
Image Builder for Firecracker MicroVMs.

Responsible for building the guest root filesystem (ext4) and downloading the kernel.
"""
import subprocess
import tempfile
from pathlib import Path


class ImageBuilder:
    def __init__(self, output_dir: str | Path | None = None):
        self.output_dir = Path(output_dir) if output_dir is not None else Path(tempfile.gettempdir()) / "firecracker_images"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.kernel_path = self.output_dir / "vmlinux.bin"
        self.rootfs_path = self.output_dir / "rootfs.ext4"

    def build_all(self):
        """Downloads kernel and builds the rootfs."""
        self.download_kernel()
        self.build_rootfs()

    def download_kernel(self):
        """Downloads a pre-compiled Firecracker-compatible kernel."""
        if self.kernel_path.exists():
            return
            
        print("Downloading kernel...")
        kernel_url = "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin"
        subprocess.run(["curl", "-L", "-o", str(self.kernel_path), kernel_url], check=True)

    def build_rootfs(self):
        """Builds an ext4 rootfs containing Python, git, and our guest agent."""
        if self.rootfs_path.exists():
            return
            
        print("Building rootfs...")
        
        # 1. Create a Dockerfile to build the base image
        dockerfile_content = """
        FROM python:3.11-slim
        
        RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*
        
        # Copy guest agent
        COPY guest_agent.py /usr/local/bin/guest_agent.py
        
        # Setup init system to run the agent
        # We replace /sbin/init with our own wrapper to start the vsock agent
        RUN echo '#!/bin/sh\\n\\nmount -t proc proc /proc\\nmount -t sysfs sysfs /sys\\n\\npython3 /usr/local/bin/guest_agent.py\\n\\npoweroff -f\\n' > /sbin/init && chmod +x /sbin/init
        """
        
        build_context = self.output_dir / "build_context"
        build_context.mkdir(exist_ok=True)
        
        (build_context / "Dockerfile").write_text(dockerfile_content)
        
        # Copy guest_agent.py into context
        current_dir = Path(__file__).parent
        (build_context / "guest_agent.py").write_text((current_dir / "guest_agent.py").read_text())
        
        # Build docker image
        subprocess.run(["docker", "build", "-t", "sentinel-guest-base", str(build_context)], check=True)
        
        # Export docker image to rootfs using a temporary container
        print("Exporting Docker image to ext4 rootfs...")
        
        # Create an empty ext4 file (e.g. 1GB)
        subprocess.run(["dd", "if=/dev/zero", f"of={self.rootfs_path}", "bs=1M", "count=1024"], check=True)
        subprocess.run(["mkfs.ext4", str(self.rootfs_path)], check=True)
        
        # Mount and copy (requires sudo, so typically done via a docker privileged container)
        subprocess.run([
            "docker", "run", "--rm", "--privileged",
            "-v", f"{self.output_dir}:/output",
            "sentinel-guest-base",
            "sh", "-c",
            "mkdir -p /mnt/rootfs && mount /output/rootfs.ext4 /mnt/rootfs && cp -r /bin /etc /lib /lib64 /root /sbin /usr /var /mnt/rootfs/ && umount /mnt/rootfs"
        ], check=True)

if __name__ == "__main__":
    builder = ImageBuilder()
    builder.build_all()
    print(f"Images ready at {builder.output_dir}")
