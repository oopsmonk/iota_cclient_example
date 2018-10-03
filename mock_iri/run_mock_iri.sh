#!/bin/bash 

# global installation 
#pip_upg="sudo -H pip install --upgrade"
#pip_ins="sudo -H pip install"

# local installation
pip_upg="pip install --upgrade"
pip_ins="pip install"

function check_pkg {
    ver=$(python -c "import ${1}; print ${1}.__version__")
    ret=$?
    if [ ! -z "${2}" ]; then
        req_ver=${2}
        echo "checking... ${1} ${req_ver}"
    else
        echo "checking... ${1}"
    fi

    if [ $ret = 0 ]; then
        if [ ! -z "${req_ver}" ] && [ "${ver}" != "${req_ver}" ]; then
            echo "pip upgrade ${1} to ${req_ver}"
            if [ "last" == "${req_ver}" ]; then
                ${pip_upg} ${1}
            else
                ${pip_upg} ${1}==${req_ver}
            fi
        fi
    else
        if [ -z "${req_ver}" ]; then
            echo "pip install ${1} "
            ${pip_ins} ${1}
        else
            echo "pip install ${1} ${req_ver}"
            ${pip_ins} ${1}==${req_ver}
        fi
    fi
}

# dependence checking
check_pkg flask 

FLASK_ENV=development python3 mock_iri.py -d
exit 0
