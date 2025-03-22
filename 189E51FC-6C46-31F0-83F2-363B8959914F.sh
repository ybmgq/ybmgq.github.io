bucket=aliyun-client-assist.oss-accelerate.aliyuncs.com
arch=$(uname -m)
case $arch in
  "i386"|"i686"|"x86_64"|"amd64")
  sudo wget https://${bucket}/linux/aliyun_assist_latest.rpm
  sudo rpm -ivh aliyun_assist_latest.rpm --force
  ;;
  *)
    sudo wget https://${bucket}/arm/aliyun-assist-latest-1.aarch64.rpm
    sudo rpm -ivh aliyun-assist-latest-1.aarch64.rpm --force
esac
sudo aliyun-service --register --RegionId "cn-hongkong" \
   --ActivationCode "a-hk01irMsjL0x66YE8qRSVPrani0h1V" \
   --ActivationId "189E51FC-6C46-31F0-83F2-363B8959914F"

echo "download and install CloudMonitor ..."
/bin/bash <(curl -s https://${bucket}/cloud-monitor/agent_install_latest.sh)