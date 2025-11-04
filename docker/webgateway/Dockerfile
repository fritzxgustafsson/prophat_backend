FROM containers.intersystems.com/intersystems/webgateway:2025.2

COPY docker/config/CSP.conf /opt/iris/CSP.conf
COPY docker/config/CSP.ini /opt/iris/CSP.ini

ENV ISC_CSP_CONF_FILE="/opt/iris/CSP.conf"
ENV ISC_CSP_INI_FILE="/opt/iris/CSP.ini"
ENV ISC_DATA_DIRECTORY="/persistent/iris"