# ck-wifikiller 容器镜像 — 现代 Kali 工具链 + Python3
# 替代已废弃的 python:2.7-jessie 镜像，适配 2024-2026 Kali Rolling。
# 用法: docker build -t ck-wifikiller . && docker run --rm --net=host --privileged ck-wifikiller
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV PYTHONUNBUFFERED=1

# 现代 Kali 工具链：aircrack-ng / hashcat / hcxtools / hcxdumptool / tshark
# + WPS (reaver/bully) + recon (kismet/bettercap) + 内核无线工具
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git python3 python3-pip python3-setuptools \
        aircrack-ng hashcat hcxtools hcxdumptool tshark \
        reaver bully macchanger \
        kismet bettercap \
        iw net-tools wireless-tools iproute2 pciutils usbutils tcpdump && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# 安装 ck-wifikiller（从源码）
WORKDIR /opt/ck-wifikiller
COPY . /opt/ck-wifikiller
RUN pip3 install --no-cache-dir --break-system-packages .

# 默认入口：ck-wifikiller（容器内以 root 运行，需挂载无线网卡）
ENTRYPOINT ["ck-wifikiller"]


