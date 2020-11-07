#!/usr/bin/env bash

if [ -n "${DEBUG}" ]; then
    set -o xtrace
fi

set -o nounset
set -o errexit
set -o pipefail


download_packages_rpm() {
    # Extract and download all availiable package
    package=$1
    dest=$2
    yum list available "${package}.x86_64" --showduplicates --enablerepo=* --disablerepo=*media* | grep "${package}.x86_64" | xargs -n3  | cut -d' ' -f2 | sed "s/.*://" | sed "s/.*/${package}-&/" | xargs --no-run-if-empty yumdownloader -x \*i686 --enablerepo=* --disablerepo=*media* --archlist=x86_64 --nogpgcheck --destdir="${dest}" > /dev/null 2>&1
}


download_packages_deb(){
    # Extract and download all availiable package
    package=$1
    dest=$2
    apt-get -q update > /dev/null 2>&1
    apt-cache madison "${package}" | awk '{print $3}' | sed "s/.*/${package}=&/" | xargs -L1 --no-run-if-empty apt-get install -y --reinstall --force-yes --download-only -o="dir::cache=${dest}" -o=Debug::NoLocking=1 > /dev/null 2>&1
}


unpack_package_deb(){
    # Unpack an rom package
    package_file=$1
    dest=$2
    dpkg -x "${package_file}" "${dest}" 2>/dev/null
}


unpack_package_rpm(){
    # Unpack an rom package
    package_file=$1
    dest=$2
    (cd "${dest}" && rpm2cpio "${package_file}" | cpio -idv 2>/dev/null)
}


list_build_id() {
    package=$1
    os=$(lsb_release -sri)
    tmp_packages=$(mktemp -d)
    chmod 755 "${tmp_packages}"

    download_packages_"${kind}" "${package}" "${tmp_packages}"
    for package_file in $(find "${tmp_packages}" -type f -name "*.deb" -or -name "*.rpm" 2>/dev/null || :)
    do
        tmp_pack=$(mktemp -d)
        unpack_package_"${kind}" "${package_file}" "${tmp_pack}"

        # Get Build ID for all executable file
        for solib in $(find "${tmp_pack}" -type f -exec file --mime-type {} \; | grep -i "application/x-sharedlib" | cut -d':' -f1)
        do
            buildid=$(eu-readelf -n "$solib" | grep "Build ID:" | cut -d: -f2)
            ${jq} -n --arg os "${os}" \
                --arg package $(basename "$package_file")  \
                --arg solib $(basename "$solib") \
                --arg buildid "${buildid}" \
                '.[$os]=(.[$package]=(.[$solib]=$buildid))'
        done
        rm -rf "${tmp_pack}"
    done
    rm -rf "${tmp_packages}"
}

prep_deb(){
    apt-get -q update > /dev/null 2>&1
    apt-get install -y -q wget lsb-release elfutils binutils > /dev/null 2>&1
}

prep_rpm(){
    yum install -q -y wget redhat-lsb-core yum-utils binutils elfutils > /dev/null 2>&1
}


if [ -f "/etc/debian_version" ]; then
    kind='deb'
else
    kind='rpm'
fi

prep_"${kind}"

jq=$(mktemp)
wget -q -O "${jq}" https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 && chmod +x "${jq}"

{
    list_build_id 'libssl1.1' && \
    list_build_id 'libssl1.0.0' && \
    list_build_id 'libc6' && \
    list_build_id 'libc-bin' && \
    list_build_id 'openssl-libs' && \
    list_build_id 'glibc';
} | ${jq} -s 'reduce .[] as $item ({}; . * $item)'

rm "${jq}"
