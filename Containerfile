# PowerOSPF in a PowerShell container. Lab use only.
#
#   podman build -f Containerfile -t powerospf .
#   podman run -it --rm --network host --cap-add NET_RAW powerospf
#
# Host networking lets sessions reach lab devices directly. OSPF uses raw IP protocol 89, which needs
# root (the default in this image) or CAP_NET_RAW, and the container must see the lab interface address.
FROM mcr.microsoft.com/powershell:lts-ubuntu-22.04

COPY . /usr/local/share/powershell/Modules/PowerOSPF
RUN rm -rf /usr/local/share/powershell/Modules/PowerOSPF/.git /usr/local/share/powershell/Modules/PowerOSPF/Containerfile \
    && pwsh -NoProfile -Command "Import-Module PowerOSPF; Get-Module PowerOSPF | Select-Object Name, Version"

ENTRYPOINT ["pwsh", "-NoLogo", "-NoExit", "-Command", "Import-Module PowerOSPF"]
