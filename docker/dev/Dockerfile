FROM intersystems/iris-community:latest-cd

USER root
COPY docker/dev/irisbuild.script /tmp/irisbuild.script
COPY docker/dev/irisstart.script /opt/iris/cfg/irisstart.script
COPY src/cls/ /opt/iris/cls/
COPY src/python/ /opt/iris/python/src/
RUN mkdir -p /opt/iris/python/lib

RUN chown -R ${ISC_PACKAGE_MGRUSER}:${ISC_PACKAGE_MGRGROUP} /opt/iris
RUN chown -R ${ISC_PACKAGE_MGRUSER}:${ISC_PACKAGE_MGRGROUP} /tmp
USER ${ISC_PACKAGE_MGRUSER}

RUN iris start IRIS && \
    iris session IRIS < /tmp/irisbuild.script && \
    iris stop IRIS quietly

RUN rm -rf /tmp/*

ENV PYTHONPATH="/opt/iris/python/src:/opt/iris/python/lib"
ENV ISC_DATA_DIRECTORY="/persistent/iris"
ENV PYTHONDONTWRITEBYTECODE=1