#!/usr/bin/env bash
set -o errexit
set -o pipefail
set -o nounset
#set -o xtrace


download_packages_deb(){
    # Extract and download all availiable package
    package=$1
    tmp_packages=$2
    apt-cache madison "${package}" | awk '{print $3}' | sed "s/.*/${package}=&/" | xargs -t -L1 apt-get install -y --reinstall --force-yes --download-only -o=dir::cache=${tmp_packages} -o=Debug::NoLocking=1 > /dev/null 2>&1
}


unpack_package_deb(){
    # Unpack an rom package
    package_file=$1
    dest=$2
    dpkg -x "${package_file}" "${dest}" 2>/dev/null
}


list_build_id() {
    package=$1
    os=$(lsb_release -sri)
    tmp_packages=$(mktemp -d)
    chmod 755 "${tmp_packages}"

    download_packages_deb "${package}" "${tmp_packages}"
    for package_file in $(ls ${tmp_packages}/**/*.{deb,rpm} 2>/dev/null || :)
    do
        tmp_pack=$(mktemp -d)
        unpack_package_deb "${package_file}" "${tmp_pack}"

        # Get Build ID for all executable file
        for solib in $(find "${tmp_pack}" -name "*.so*" -type f)
        do
            buildid=$(eu-readelf -n $solib | grep "Build ID:" | cut -d: -f2)
            ./jq -n --arg os "${os}" \
                --arg package $(basename $package_file)  \
                --arg solib $(basename $solib) \
                --arg buildid "${buildid}" \
                '.[$os]=(.[$package]=(.[$solib]=$buildid))'
        done
        rm -rf "${tmp_pack}"
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
