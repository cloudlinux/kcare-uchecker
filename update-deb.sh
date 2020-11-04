#!/usr/bin/env bash
set -o errexit
set -o pipefail
set -o nounset
#set -o xtrace


list_build_id() {
    package=$1
    os=$(lsb_release -sri)
    tmp_packages=$(mktemp -d)
    chmod 755 "${tmp_packages}"

    # Extract and download all availiable package
    apt-cache madison "${package}" | awk '{print $3}' | sed "s/.*/${package}=&/" | xargs -t -L1 apt-get install -y --reinstall --force-yes --download-only -o=dir::cache=${tmp_packages} -o=Debug::NoLocking=1 > /dev/null 2>&1
    #ackage ssearch --allow-downgrades

    for package_file in $(ls ${tmp_packages}/**/*.deb 2>/dev/null || :)
    do
        TMP_PACK=$(mktemp -d)
        # Unpack an rom package
        dpkg -x $package_file "${TMP_PACK}" 2>/dev/null
        # Get Build ID for all executable file
        for solib in $(find "${TMP_PACK}" -name "*.so*" -type f)
        do
            buildid=$(eu-readelf -n $solib | grep "Build ID:" | cut -d: -f2)
            ./jq -n --arg os "${os}" \
                --arg package $(basename $package_file)  \
                --arg solib $(basename $solib) \
                --arg buildid "${buildid}" \
                '.[$os]=(.[$package]=(.[$solib]=$buildid))'
        done
        rm -rf "${TMP_PACK}"
    done
    rm -rf "${tmp_packages}"
}

apt-get -q update > /dev/null 2>&1
apt-get install -y -q wget lsb-release elfutils binutils > /dev/null 2>&1
wget -q -O ./jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64
chmod +x ./jq

{
    list_build_id 'libssl1.1' && \
    list_build_id 'libssl1.0.0' && \
    list_build_id 'libc6';
    list_build_id 'libc-bin';
} | ./jq -s 'reduce .[] as $item ({}; . * $item)'
