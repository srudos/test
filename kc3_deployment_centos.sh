#!/bin/bash -xe
set -x
databaseName=$1
dbEndpoint=$2
databaseLoginName=$3
base64DatabaseLoginPassword=$4
optenv=$5
subscriptionid=$6
applicationid=$7
applicationkey=$8
tenantid=$9
storageName=${10}
storageContainerName=${11}
newtenDbName=${12}
s3endpointPrefix=${13}
alluxio_package=alluxio-bin.tar.gz
clickhouse_package=clickhouse-22.3.3.44.tar.gz
trust_cidrs=${14##*:}
internal=${15}
tags=${16}
blobEndpoint=${17}
zoo_my_id=${18}
kc_private_ip=${19}
kc_ha_private_ip=${20}
zk_private_ip=${21}
monitor=${22}
blobScheme=${23}
lokiOption=${24}
image_plan_custom=${25}
image_plan_name=${26}
image_plan_publisher=${27}
image_plan_product=${28}
image_custom=${29}
image_publisher=${30}
image_offer=${31}
image_sku=${32}
image_version=${33}
protocol=${34}
fixed_ssh_username=${35}
dbEngineType=${36}
localStore=${37}
# put this paramter at the end, because it may be ""
azureCommonPublicBackendPoolId=${38}

databaseLoginPassword=$(echo -n $base64DatabaseLoginPassword | base64 -d)

packageLocation="${s3endpointPrefix}"
if [ "${localStore}" != "false" ] ; then
  packageLocation="/data"
fi

sed -i 's/^SELINUX=.*/SELINUX=disable/g' /etc/sysconfig/selinux
sed -i 's/^SELINUX=.*/SELINUX=disable/g' /etc/selinux/config
setenforce 0

systemctl stop firewalld
systemctl disable firewalld

configOpenFiles() {
  #config system service
  echo "DefaultLimitNOFILE=65536" >>/etc/systemd/system.conf
  echo "DefaultLimitNPROC=65536" >>/etc/systemd/system.conf
  #change limit of system
  echo "root soft     nofile         65535" >>/etc/security/limits.conf
  echo "root hard     nofile         65535" >>/etc/security/limits.conf
  echo "root soft     nproc          65535" >>/etc/security/limits.conf
  echo "root hard     nproc          65535" >>/etc/security/limits.conf
  echo "session required    pam_limits.so" >>/etc/pam.d/common-session
  ulimit -n 65535
}
configOpenFiles

if [ "${kc_ha_private_ip}" = "null" ]; then
  ZOO_SERVERS="server.1=localhost:2888:3888;2181"
  ZOOKEEPER_CONNECT_STRING="${kc_private_ip}:2181"
  NACOS_CONNECT_STRING="${kc_private_ip}:8848"
  ZOOKEEPER_EXPORTER_HOSTS="${kc_private_ip}:2181"
else
  ZOO_SERVERS="server.1=${kc_private_ip}:2888:3888;2181 server.2=${kc_ha_private_ip}:2888:3888;2181 server.3=${zk_private_ip}:2888:3888;2181"
  ZOOKEEPER_CONNECT_STRING="${kc_private_ip}:2181,${kc_ha_private_ip}:2181,${zk_private_ip}:2181"
  NACOS_CONNECT_STRING="${kc_private_ip}:8848,${kc_ha_private_ip}:8848,${zk_private_ip}:8848"
  ZOOKEEPER_EXPORTER_HOSTS="${kc_private_ip}:2181,${kc_ha_private_ip}:2181,${zk_private_ip}:2181"
fi
# install docker
if sudo yum list installed | grep rhui-azure-rhel7
then
  sudo yum install -y rhui-azure-rhel7 --disablerepo='*' --enablerepo='*microsoft*'
fi

sudo yum install -y docker
sed -i "s|^OPTIONS=.*|OPTIONS='--log-driver=journald --signature-verification=false'|g" /etc/sysconfig/docker

sudo systemctl daemon-reload
sudo systemctl enable docker
sudo systemctl start docker

# install azure cli
sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
sudo sh -c 'echo -e "[azure-cli]
name=Azure CLI
baseurl=https://packages.microsoft.com/yumrepos/azure-cli
enabled=1
gpgcheck=1
gpgkey=https://packages.microsoft.com/keys/microsoft.asc" > /etc/yum.repos.d/azure-cli.repo'
sudo yum install -y azure-cli

az cloud set -n $optenv
az login --service-principal -u $applicationid -p=${applicationkey} --tenant $tenantid >>/tmp/azlogin.log 2>&1
#set default subscription
az account set --subscription ${subscriptionid}
storageAccountKey=$(az storage account keys list --account-name  $storageName --query [0].{accountKey:value} --output tsv)

for var in $( seq 1 200 )
do
  if [ -z $storageAccountKey ]; then
    sleep 30s
    storageAccountKey=$(az storage account keys list --account-name  $storageName --query [0].{accountKey:value} --output tsv)
  fi
done

export AZURE_STORAGE_ACCOUNT=$storageName
export AZURE_STORAGE_ACCESS_KEY=$storageAccountKey
az storage container create -n $storageContainerName --account-name $storageName

# install goofys
wget -nv --no-check-certificate $s3endpointPrefix/tools/goofys.tar.gz
tar zxf goofys.tar.gz && chmod +x goofys && mv ./goofys /usr/bin/

# mount container to /data1
mkdir -p /data1
echo "[storage]" >>/root/.azure/config
echo "account = $storageName" >>/root/.azure/config
echo "key = $storageAccountKey" >>/root/.azure/config

# start goofys service for mount blob to data1 when reboot vm
mkdir -p /opt/kyligence
sudo cat >> /opt/kyligence/mount_goofys.sh <<EOL
#!/bin/sh -e
goofys --stat-cache-ttl 1s --type-cache-ttl 1s $blobScheme://$storageContainerName@$storageName.$blobEndpoint /data1
systemctl restart docker
exit 0
EOL
sudo chmod a+x /opt/kyligence/mount_goofys.sh
sudo cat >> /etc/systemd/system/mount_goofys.service <<EOL
[Unit]
Description=Mount goofys when kyligence cloud bootstrap
After=network.target
[Service]
User=root
Type=forking
ExecStart=/opt/kyligence/mount_goofys.sh
TimeoutSec=0
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOL
sudo systemctl enable mount_goofys
sudo systemctl start mount_goofys

if [ "$dbEngineType" = "mysql" ]; then
cat <<EOF >> /tmp/cloud.properties
# Database connection
spring.datasource.url=jdbc:mysql://$databaseName.mysql$dbEndpoint:3306/cloud?autoReconnect=true&createDatabaseIfNotExist=true&UseUnicode=true&characterEncoding=utf8&serverTimezone=UTC
spring.datasource.username=$databaseLoginName@$databaseName
spring.datasource.password=$databaseLoginPassword
EOF
elif [ "$dbEngineType" = "postgresql" ]; then
cat <<EOF >> /tmp/cloud.properties
# Database connection
spring.datasource.url=jdbc:postgresql://$databaseName.postgres$dbEndpoint:5432/cloud?UseUnicode=true&characterEncoding=utf8&characterSetResults=UTF-8&serverTimezone=UTC
spring.datasource.username=$databaseLoginName@$databaseName
spring.datasource.password=$databaseLoginPassword
kyligence.cloud.jdbc-type=postgresql
spring.datasource.driver-class-name=org.postgresql.Driver
spring.liquibase.change-log=classpath:db/changelog-pg/db.changelog-master.xml
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQL9Dialect
spring.quartz.properties.org.quartz.jobStore.driverDelegateClass=org.quartz.impl.jdbcjobstore.PostgreSQLDelegate
EOF
else
  echo "unexpected DB Engine Type env:$dbEngineType"
  exit 1
fi

cat <<EOF >> /tmp/cloud.properties
# Native cloud platform: AWSChinaCloud,AWSGlobal,AzureChinaCloud,AzureCloud,Aliyun,HuaweiCloud,HuaweiChinaCloud,GoogleCloud
kyligence.cloud.platform=$optenv
# Kyligence Enterprise
kyligence.enterprise.base-dir=/tmp/kyligence
on.aws.cn.marketplace=false
on.aws.global.marketplace=false
aws.marketplace.credential=/tmp/credential
kyligence.cloud.download-resources.path=resources
#azure credentials
kyligence.cloud.azure-protocol=$protocol
kyligence.cloud.azure-credentials.subscription-id=$subscriptionid
kyligence.cloud.azure-credentials.application-id=$applicationid
kyligence.cloud.azure-credentials.application-key=$applicationkey
kyligence.cloud.azure-credentials.tenant-id=$tenantid
kyligence.cloud.azure-credentials.storage-account-name=$storageName
kyligence.cloud.azure-credentials.container-name=$storageContainerName
kyligence.cloud.azure-credentials.storage-account-key=$storageAccountKey
kyligence.cloud.azure-image.plan-custom=$image_plan_custom
kyligence.cloud.azure-image.plan-name=$image_plan_name
kyligence.cloud.azure-image.plan-publisher=$image_plan_publisher
kyligence.cloud.azure-image.plan-product=$image_plan_product
kyligence.cloud.azure-image.custom=$image_custom
kyligence.cloud.azure-image.publisher=$image_publisher
kyligence.cloud.azure-image.offer=$image_offer
kyligence.cloud.azure-image.sku=$image_sku
kyligence.cloud.azure-image.version=$image_version
kyligence.cloud.ke-package-name=Kyligence-Enterprise-4.0.0-latest.tar.gz
kyligence.cloud.spark-package-name=spark-newten-latest.tgz
kyligence.cloud.ki-package-name=Kyligence-Insight-Image-latest.tar.gz
kyligence.cloud.mdx-package-name=Kyligence-MDX-Image-latest.tar.gz
kyligence.cloud.ke-database-name=$newtenDbName
kyligence.cloud.trust-cidr=$trust_cidrs
kyligence.cloud.extra-tags=$tags
kyligence.cloud.internal=$internal
kyligence.cloud.azure-common-public-backend-pool-id=$azureCommonPublicBackendPoolId
kyligence.cloud.zookeeper-connect-string=$ZOOKEEPER_CONNECT_STRING
kyligence.cloud.ke-jvm-percentage=0.5
kyligence.cloud.influxdb-bind-address=$kc_private_ip:8088
kyligence.cloud.influxdb-url=$kc_private_ip:8086
kyligence.cloud.package-location=$packageLocation
kyligence.cloud.azure-credentials.schema=$blobScheme
kyligence.cloud.extra-ssh-user-name=_kcadmin
kyligence.cloud.monitor.alertmanager-url=$kc_private_ip:9093
kyligence.cloud.monitor.prometheus-url=$kc_private_ip:9090
EOF

if [ "$dbEngineType" = "mysql" ]; then
cat <<EOF >> /tmp/cloud.properties
nacos.config.server-addr=$NACOS_CONNECT_STRING
EOF
fi

# config loki configuration if needed
if [ "$lokiOption" = "enable" ];then
  cat << EOF >> /tmp/cloud.properties
kyligence.cloud.enable-loki=enable
kyligence.cloud.loki-server-host=$kc_private_ip
kyligence.cloud.loki-server-port=3100
EOF
fi

#install loki and promtail if needed
mkdir -p /data1/packages
current_ip=$(hostname -i)
if [ "$lokiOption" = "enable" ];then
  if [ "$current_ip" = "$kc_private_ip" ];then
    loki_env=$optenv
    if [ "$optenv" = "AzureCloud" ];then
      loki_env="AzureGlobal"
    fi
    echo Begin install Loki Server
    wget -nv --no-check-certificate $s3endpointPrefix/resources/kyligence-loki.tar

    mkdir -p /opt/kyligence/loki
    mkdir -p /opt/kyligence/loki/index
    # loki is ran as user loki and need permission to put its index file here in the container
    chmod -R 777 /opt/kyligence/loki/index
    if [ -f ./kyligence-loki.tar ];then
      docker load --input ./kyligence-loki.tar && rm -rf ./kyligence-loki.tar
    fi

    sudo cat > /opt/kyligence/loki/loki-config.yaml <<EOL
auth_enabled: false
server:
  http_listen_port: 3100
ingester:
  lifecycler:
    address: 127.0.0.1
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1
    final_sleep: 0s
  chunk_idle_period: 5m
  chunk_retain_period: 30s
  chunk_target_size: 1536000
  max_chunk_age: 30m
  max_transfer_retries: 0
schema_config:
  configs:
    - from: 2020-08-18
      store: boltdb
      object_store: azure
      schema: v11
      index:
        prefix: loki_index_
        period: 168h
storage_config:
  boltdb:
    directory: /loki
  azure:
    environment: $loki_env
    container_name: $storageContainerName
    account_name: $storageName
    account_key: $storageAccountKey
limits_config:
  enforce_metric_name: false
  reject_old_samples: true
  reject_old_samples_max_age: 168h
chunk_store_config:
  max_look_back_period: 0s
table_manager:
  retention_deletes_enabled: false
  retention_period: 0s
EOL
    docker run -d --network=host --restart=always --cpus=2 --memory="2g" -v /opt/kyligence/loki/index:/loki -v /opt/kyligence/loki/loki-config.yaml:/mnt/config/loki-config.yaml -p 3100:3100 kyligence-loki:latest -config.file=/mnt/config/loki-config.yaml
  fi

  # prepare to start a promtail
  wget -nv --no-check-certificate $s3endpointPrefix/resources/promtail.tar.gz
  if [ -f ./promtail.tar.gz ];then
    cp ./promtail.tar.gz /data1/packages/
    tar zxf ./promtail.tar.gz && chmod +x ./promtail && mv ./promtail /usr/bin/ && rm -rf ./promtail.tar.gz
  fi
  mkdir -p /opt/kyligence/promtail
  current_private_ip=$(hostname -i)
  identifier=${databaseName%*db}
  echo "Parsed identifier:$identifier"
  sudo cat > /opt/kyligence/promtail/promtail-config.yaml <<EOL
server:
  http_listen_port: 9080
  grpc_listen_port: 0
positions:
  filename: /opt/kyligence/promtail/positions.yaml
clients:
  - url: http://${kc_private_ip}:3100/loki/api/v1/push
scrape_configs:
- job_name: kc
  static_configs:
  - targets:
      - localhost
    labels:
      service: kc
      host: ${current_private_ip}
      filename: cloud.log
      stack: ${identifier}
      __path__: /data/kyligence_cloud_log/cloud.log
EOL
sudo cat >> /etc/systemd/system/promtail.service <<EOL
[Unit]
Description=Promtail service
[Service]
Type=simple
ExecStart=/usr/bin/promtail -config.file=/opt/kyligence/promtail/promtail-config.yaml
Restart=always
RestartSec=30
StartLimitInterval=400
StartLimitBurst=10
[Install]
WantedBy=multi-user.target
EOL
  systemctl enable promtail
  systemctl start promtail
fi

# config ssh username if specified.
if [ "$fixed_ssh_username" != "-" ];then
  cat << EOF >> /tmp/cloud.properties
kyligence.cloud.azure-credentials.fixed-admin-username=$fixed_ssh_username
kyligence.cloud.extra-ssh-user-name=_kcadmin
EOF
fi

mkdir -p /data1/kyligence_cloud
NACOS_MODE="standalone"
nacosDbEndpoint=""
if [ "$dbEngineType" = "mysql" ]; then
nacosDbEndpoint=".mysql$dbEndpoint"
elif [ "$dbEngineType" = "postgresql" ]; then
nacosDbEndpoint=".postgres$dbEndpoint"
fi

if [ "$dbEngineType" = "mysql" ]; then
#install and config nacos
wget -nv --no-check-certificate $s3endpointPrefix/resources/nacos.tar.gz && tar -xf nacos.tar.gz && docker load --input ./nacos.tar
nacosServerIp=$kc_private_ip
if [ "${zoo_my_id}" = "2" ]; then
  nacosServerIp=${kc_ha_private_ip}
fi

if [ "$nacosServerIp:8848" != "$NACOS_CONNECT_STRING" ]; then
  NACOS_MODE="cluster"
fi

cat <<EOF >/tmp/nacos.properties
spring.datasource.password=$databaseLoginPassword
EOF
mkdir -p /data1/kyligence_cloud/nacos_conf
mv /tmp/nacos.properties /data1/kyligence_cloud/nacos_conf
docker volume create --driver local --opt type=none --opt device=/data1/kyligence_cloud/nacos_conf/ --opt o=bind nacos_conf

docker run -d \
-e MODE=${NACOS_MODE} \
-e SPRING_DATASOURCE_PLATFORM=mysql \
-e NACOS_SERVER_IP=${nacosServerIp} \
-e NACOS_SERVERS=${NACOS_CONNECT_STRING} \
-e MYSQL_SERVICE_HOST=${databaseName}${nacosDbEndpoint} \
-e MYSQL_SERVICE_PORT=3306 \
-e MYSQL_SERVICE_USER=$databaseLoginName@$databaseName \
-e MYSQL_SERVICE_DB_NAME=nacos \
-p 8848:8848 \
--name nacos \
--volume nacos_conf:/home/nacos/nacos_conf \
--restart=always \
nacos
fi

#monitor
if [ "$monitor" = "enable" ]
then
  wget -nv --no-check-certificate $s3endpointPrefix/resources/Kyligence-Monitor-latest.tar.gz
  tar zxf Kyligence-Monitor-latest.tar.gz
  docker load --input ./monitor_latest.tar
  mkdir /monitor_data
  diskname=$(ls -l /dev/disk/azure/scsi1/lun0 | grep -wo sd.)
  sudo parted /dev/${diskname} --script mklabel gpt mkpart xfspart xfs 0% 100%
  sudo mkfs.xfs /dev/${diskname}1
  partprobe /dev/${diskname}1
  sudo mount /dev/${diskname}1 /monitor_data
  diskUUID=$(blkid /dev/${diskname}1 | awk -F '"' '{print $2}')
  echo "UUID=${diskUUID} /monitor_data auto defaults,nofail  0  2" >> /etc/fstab
  image_tag=$(docker load --input monitor_latest.tar| awk 'END {print}'| awk '{print $3}')
  mkdir -p /monitor_data/conf/
  mkdir -p /monitor_data/data/
  mkdir -p /monitor_data/log/
  curl -H Metadata:True "http://169.254.169.254/metadata/instance?api-version=2017-08-01&format=json" > message.tmp
  region_value=$(awk -F '"' '{print $6}'  message.tmp)
  wget -nv --no-check-certificate $s3endpointPrefix/resources/monitor_azure.yml
  result=$(echo $region_value | grep "China")
  if [ "${result}" != "" ] ; then
     sed -i "s/{{environment_value}}/AzureChinaCloud/" monitor_azure.yml
  else
     sed -i "s/{{environment_value}}/AzurePublicCloud/" monitor_azure.yml
  fi
  subscription_value=$(awk -F '"' '{print $46}'  message.tmp)
  sed -i "s/{{subscription_id}}/$subscription_value/g" monitor_azure.yml
  sed -i "s/{{azure_tenant_id}}/$tenantid/g" monitor_azure.yml
  sed -i "s/{{azure_client_id}}/$applicationid/g" monitor_azure.yml
  sed -i "s|{{azure_client_secret}}|$applicationkey|g" monitor_azure.yml
  if [ "${kc_ha_private_ip}" = "null" ]; then
     sed -i "s/{{kyligence_cloud_address}}/\'${kc_private_ip}:8079\'/g" monitor_azure.yml
  else
     sed -i "s/{{kyligence_cloud_address}}/\'${kc_private_ip}:8079\',\'${kc_ha_private_ip}:8079\'/g" monitor_azure.yml
  fi

  cp monitor_azure.yml /monitor_data/conf/prometheus.yml
  wget -nv --no-check-certificate $s3endpointPrefix/resources/alert.rules
  cp alert.rules /monitor_data/conf/alert.rules
  wget -nv --no-check-certificate $s3endpointPrefix/resources/alert_kc.rules
  cp alert_kc.rules /monitor_data/conf/alert_kc.rules
  docker run -d --restart=always --name monitor -p 9090:9090 --network=host  -v /monitor_data/conf/:/etc/prometheus  -v /monitor_data/data/:/prometheus -v /monitor_data/log/:/prometheus/log "$image_tag"

  wget -nv --no-check-certificate $s3endpointPrefix/resources/azure_metrics_exporter.yml
  mkdir -p /monitor_data/azure_metrics_exporter/
  sed -i "s/{{SUBCRIPTION_ID_VALUE}}/$subscription_value/g" azure_metrics_exporter.yml
  if [ "${result}" != "" ] ; then
     sed -i "s|{{MANAGER_URL_VALUE}}|https://management.chinacloudapi.cn/|" azure_metrics_exporter.yml
     sed -i "s|{{AUTHORITY_URL_VALUE}}|https://login.chinacloudapi.cn/|" azure_metrics_exporter.yml
  else
     sed -i "s|{{MANAGER_URL_VALUE}}|https://management.azure.com/|" azure_metrics_exporter.yml
     sed -i "s|{{AUTHORITY_URL_VALUE}}|https://login.microsoftonline.com/|" azure_metrics_exporter.yml
  fi
  cp azure_metrics_exporter.yml /monitor_data/azure_metrics_exporter/config.yml
  docker load --input ./azure-metrics-exporter_latest.tar
  image_tag_metrics_exporter=$(docker load --input azure-metrics-exporter_latest.tar| awk 'END {print}'| awk '{print $3}')
  docker run --restart=always -d --name azure_metrics -p 9276:9276 -v /monitor_data/azure_metrics_exporter/config.yml:/config.yml "$image_tag_metrics_exporter" --config.file=/config.yml
  docker load --input ./zookeeper-exporter_latest.tar
  image_tag_zookeeper_exporter=$(docker load --input zookeeper-exporter_latest.tar| awk 'END {print}'| awk '{print $3}')
  docker run --restart=always -d --name zookeeper_exporter -p 9141:9141 "$image_tag_zookeeper_exporter" -zk-hosts ${ZOOKEEPER_EXPORTER_HOSTS}

  #alertmanager
  mkdir -p /data1/kyligence_cloud/alertconf
  mkdir -p /data1/kyligence_cloud/alertconf/templates
  docker load --input ./alertmanager_latest.tar
  image_tag_alertmanager=$(docker load --input alertmanager_latest.tar| awk 'END {print}'| awk '{print $3}')
  wget -nv --no-check-certificate $s3endpointPrefix/resources/alertmanager.yml
  cp alertmanager.yml /data1/kyligence_cloud/alertconf/alertmanager.yml
  wget -nv --no-check-certificate $s3endpointPrefix/resources/tiered_storage_alert.tmpl
  cp tiered_storage_alert.tmpl /data1/kyligence_cloud/alertconf/templates/tiered_storage_alert.tmpl
  wget -nv --no-check-certificate $s3endpointPrefix/resources/kyligence_cloud_alert.tmpl
  cp kyligence_cloud_alert.tmpl /data1/kyligence_cloud/alertconf/templates/kyligence_cloud_alert.tmpl
  docker run --restart=always -d --name alertmanager -p 9093:9093 -v /data1/kyligence_cloud/alertconf/:/etc/alertmanager/ "$image_tag_alertmanager"
# install blackbox_exporter
  sudo wget -nv --no-check-certificate $s3endpointPrefix/resources/blackbox.yml
  blackbox_images=$(sudo docker load --input ./blackbox_exporter.tar | awk 'END {print}' | awk '{print $3}')
  sudo mkdir -p /monitor_data/blackbox_exporter
  sudo cp ./blackbox.yml /monitor_data/blackbox_exporter
  sudo docker run -d --network=host --restart=always --name blackbox_exporter -v /monitor_data/blackbox_exporter:/etc/blackbox_exporter/ ${blackbox_images} --config.file=/etc/blackbox_exporter/blackbox.yml
fi

mkdir -p /data/influxdb
mkdir -p /data/kyligence_cloud_log
whoami >/tmp/whoami
wget -nv --no-check-certificate $s3endpointPrefix/resources/docker_influxdb.tar && docker load --input ./docker_influxdb.tar
wget -nv --no-check-certificate $s3endpointPrefix/resources/docker_zookeeper.tar && docker load --input ./docker_zookeeper.tar
wget -nv --no-check-certificate $s3endpointPrefix/scripts/upgrade_kyligence.sh -P /opt && chmod +x /opt/upgrade_kyligence.sh
docker run --network=host -d --restart=always --name influxdbsvr -v /data/influxdb:/var/lib/influxdb influxdb:latest
docker run --network=host -d --restart=always --env ZOO_4LW_COMMANDS_WHITELIST=* --env ZOO_MY_ID=${zoo_my_id} --env ZOO_SERVERS="${ZOO_SERVERS}" --name zookeeper zookeeper:latest

wget -nv --no-check-certificate $s3endpointPrefix/resources/newten-packages.tar.gz
wget -nv --no-check-certificate $s3endpointPrefix/resources/node_exporter.tar.gz
tar zxf newten-packages.tar.gz

cp ./$alluxio_package /data1/packages/$alluxio_package
cp ./spark-newten-latest.tgz /data1/packages/spark-newten-latest.tgz
cp ./Kyligence-Enterprise-4.0.0-latest.tar.gz /data1/packages/Kyligence-Enterprise-4.0.0-latest.tar.gz
cp ./Kyligence-Insight-Image-latest.tar.gz /data1/packages/Kyligence-Insight-Image-latest.tar.gz
cp ./Kyligence-MDX-Image-latest.tar.gz /data1/packages/Kyligence-MDX-Image-latest.tar.gz
cp ./node_exporter.tar.gz /data1/packages/
cp ./$clickhouse_package /data1/packages/$clickhouse_package

wget -nv --no-check-certificate $s3endpointPrefix/packages/kyligence_lightning.tar.gz && tar zxf kyligence_lightning.tar.gz && docker load --input ./kyligence_lightning.tar
rm -rf /data/kyligence_share && mkdir -p /data/kyligence_share
rm -rf /data/kyligence_terra && mkdir -p /data/kyligence_terra
wget -nv $s3endpointPrefix/resources/ansible.tar.gz && cp ./ansible.tar.gz /data/kyligence_share/
docker volume create --driver local --opt type=none --opt device=/data/kyligence_terra --opt o=bind terra_vol

wget -nv --no-check-certificate $s3endpointPrefix/resources/blacklist.properties
wget -nv --no-check-certificate $s3endpointPrefix/resources/KyligenceCloudLibrary.csv
wget -nv --no-check-certificate $s3endpointPrefix/resources/configuration_center_system_config.properties
# bind mount directory
mkdir -p /data1/kyligence_cloud && mkdir -p /data1/kyligence_cloud/authorized_keys && mkdir -p /data1/kyligence_cloud/diag_tmp && mkdir -p /data1/kyligence_cloud/dep_tmp && mkdir -p /data1/kyligence_cloud/upload_tmp && mkdir -p /data1/kyligence_cloud/conf && mkdir -p /data1/kyligence_cloud/terra_var && mkdir -p /data1/kyligence_cloud/cert && mkdir -p /data1/kyligence_cloud/alertconf
mv -f /tmp/cloud.properties /data1/kyligence_cloud/conf/
mv -f ./blacklist.properties /data1/kyligence_cloud/conf/
mv -f ./KyligenceCloudLibrary.csv /data1/kyligence_cloud/conf/
mv -f ./configuration_center_system_config.properties /data1/kyligence_cloud/conf/
docker volume create --driver local --opt type=none --opt device=/data1/kyligence_cloud/authorized_keys/ --opt o=bind key_vol
docker volume create --driver local --opt type=none --opt device=/data1/kyligence_cloud/diag_tmp/ --opt o=bind diag_vol
docker volume create --driver local --opt type=none --opt device=/data1/kyligence_cloud/dep_tmp/ --opt o=bind dep_vol
docker volume create --driver local --opt type=none --opt device=/data1/kyligence_cloud/conf/ --opt o=bind conf_vol
docker volume create --driver local --opt type=none --opt device=/data1/kyligence_cloud/terra_var/ --opt o=bind var_vol
docker volume create --driver local --opt type=none --opt device=/data1/kyligence_cloud/upload_tmp/ --opt o=bind upload_vol
docker volume create --driver local --opt type=none --opt device=/data1/kyligence_cloud/alertconf/ --opt o=bind alertmanager_vol

# support package_location in local
mkdir -p /data1/tools
wget --no-check-certificate $s3endpointPrefix/tools/libzstd-1.5.0-1.el7.x86_64.rpm -P /data1/tools
wget --no-check-certificate $s3endpointPrefix/tools/rinetd-0.62-9.el7.nux.x86_64.rpm -P /data1/tools
wget --no-check-certificate $s3endpointPrefix/tools/blobfuse.tar.gz -P /data1/tools
wget --no-check-certificate $s3endpointPrefix/tools/goofys.tar.gz -P /data1/tools
wget --no-check-certificate $s3endpointPrefix/tools/bbcp.tar.gz -P /data1/tools
wget --no-check-certificate $s3endpointPrefix/tools/blobfuse-RHEL.rpm -P /data1/tools
wget --no-check-certificate $s3endpointPrefix/tools/blobfuse-CentOS.rpm -P /data1/tools
# end

env="azure"
naco_mode="cluster"
if [ "${kc_ha_private_ip}" = "null" ]; then
    naco_mode="standalone"
fi
if [ "$protocol" = "HTTPS" ];then
docker volume create --driver local --opt type=none --opt device=/data1/kyligence_cloud/cert/ --opt o=bind cert_vol
docker run -d --ulimit nofile=65535:65535 --network=host --restart=always --name kyligence_cloud -e PROTOCOL=$protocol -e kc_private_ip=$kc_private_ip -e kc_ha_private_ip=$kc_ha_private_ip -e zk_private_ip=$zk_private_ip -e naco_mode=$NACOS_MODE -e env=$env --volume cert_vol:/opt/kyligence_cloud/cert --volume var_vol:/opt/kyligence_cloud/terra_var --volume conf_vol:/opt/kyligence_cloud/conf -v /data/kyligence_share:/opt/share -v /data/kyligence_cloud_log:/opt/kyligence_cloud/log  -v alertmanager_vol:/opt/kyligence_cloud/alertconf --volume terra_vol:/opt/kyligence_cloud/terra --volume key_vol:/opt/kyligence_cloud/authorized_keys --volume diag_vol:/opt/kyligence_cloud/diag_tmp --volume dep_vol:/opt/kyligence_cloud/dep_tmp --volume upload_vol:/opt/kyligence_cloud/upload_tmp -v /data1:/data kyligence/lightning:latest
else
docker run -d --ulimit nofile=65535:65535 --network=host --restart=always --name kyligence_cloud -e PROTOCOL=$protocol -e kc_private_ip=$kc_private_ip -e kc_ha_private_ip=$kc_ha_private_ip -e zk_private_ip=$zk_private_ip -e naco_mode=$NACOS_MODE -e env=$env --volume var_vol:/opt/kyligence_cloud/terra_var --volume conf_vol:/opt/kyligence_cloud/conf -v /data/kyligence_share:/opt/share -v /data/kyligence_cloud_log:/opt/kyligence_cloud/log  -v alertmanager_vol:/opt/kyligence_cloud/alertconf --volume terra_vol:/opt/kyligence_cloud/terra --volume key_vol:/opt/kyligence_cloud/authorized_keys --volume diag_vol:/opt/kyligence_cloud/diag_tmp --volume dep_vol:/opt/kyligence_cloud/dep_tmp --volume upload_vol:/opt/kyligence_cloud/upload_tmp -v /data1:/data kyligence/lightning:latest
fi

  sudo mkdir -p  /opt/kyligence/monitor
  sudo cp node_exporter.tar.gz  /opt/kyligence/monitor/
  sudo tar zxf /opt/kyligence/monitor/node_exporter.tar.gz -C /opt/kyligence/monitor/
  sudo cat >> /etc/systemd/system/node_exporter.service <<EOL
[Unit]
Description=Service which runs Node Exporter for Prometheus scraping

[Service]
User=root
ExecStart=/opt/kyligence/monitor/node_exporter/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOL
  sudo systemctl enable node_exporter
  sudo systemctl start node_exporter
