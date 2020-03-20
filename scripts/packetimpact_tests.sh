#!/bin/bash

# Copyright 2019 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

source $(dirname $0)/common.sh

install_runsc_for_test runsc-d

cat ~/.ssh/authorized_keys

cat << EOF >> ~/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDP+B6tdmHQwHM2WFPLBATkML9h8eiG/wsmji3mzf4Eg+nAyLVi0+qFWjvTjJBgBIKmqwOrh6rUGhVeOyvvYo3Q3vf+N11h+KRUqKZlR7Bq2vC2BcXNzYsO2LIJd3mVW1nCjsdyxxY2BH/HFXj9TEjiIN5s7tejI+UhSmWFwY1X4UdiWdjOaDJQ0yBmXK7LG/Yxo7NOY8F109mLvGKSKc6bNbv/Pnj/Ldu2LEdF2Q5+zWHP1jA9+EIiX7CaQ5ak0OU+vfh5WsldGg7fmVpsE8J3AfEQkqsOmv/SieTCAcTUwNhpSGBBdNxAWmhi1BItNHVzQeZbAs/7LgfPJ4Vc4rhDwlsnNwgIYEymQHTbxg+qiaH8GrBrtK8xhqCxNNuw221lQlh+K2aPW5eC+rOQEV31izek3+TcAFnpGvZsORddo2vYbTYOUk6O9Ydf6v6ScN79EW3MmiD9PYMsGOy0IovoK5WhfyIe9BpF5KuSUv4XZ+SWxiIpbH7QC0M749Fswll6WqivsSXN/aLEr/d3fZUl8Bx7qkWVE+j7xeoZXkzI0pxhQQjDXdPEWnj6lGrX6GVnVbi1jS3qpoph7e8UuaMojE4paoXG1yGmwDTlLwzwUEIj2wTK33nmkiucy7llx0GtrfCsNXeo+k+9yO6654fdfe8KsrvJ4X2cEh4fnPGurQ== eyalsoha@gmail.com

EOF

cat ~/.ssh/authorized_keys

external_ip=$(curl -s -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)
echo "INSTANCE_EXTERNAL_IP=${external_ip}"
sleep 3600

test_runsc $(bazel query "attr(tags, packetimpact, tests(//test/packetimpact/...))")
