#!/usr/bin/env bash
set -o errexit
set -o pipefail
set -o nounset
set -o xtrace


list_build_id() {
    package=$1
    os=$(lsb_release -sri)
    tmp_packages=$(mktemp -d)

    # Extract and download all availiable package
    yum list available "${package}.x86_64" --showduplicates --enablerepo=* --disablerepo=*media* | grep "${package#}.x86_64" | xargs -n3  | cut -d' ' -f2 | sed "s/.*://" | sed "s/.*/${package}-&/" | xargs yumdownloader -x \*i686 --enablerepo=* --disablerepo=*media* --archlist=x86_64 --nogpgcheck --destdir="${tmp_packages}" > /dev/null 2>&1

    for package_file in $(ls ${tmp_packages}/*.rpm || :)
    do
        TMP_PACK=$(mktemp -d)
        # Unpack an rom package
        (cd "${TMP_PACK}" && rpm2cpio $package_file | cpio -idv 2>/dev/null)
        # Get Build ID for all executable file
        for solib in $(find "${TMP_PACK}" -executable -type f)
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

yum install -q -y wget redhat-lsb-core yum-utils binutils elfutils > /dev/null 2>&1
wget -q -O ./jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64
chmod +x ./jq

{
    list_build_id openssl-libs && \
    list_build_id glibc;
} | ./jq -s 'reduce .[] as $item ({}; . * $item)'
