FROM intersystems/iris-community:latest-cd

USER root
COPY config/irisbuild.script /tmp/irisbuild.script
COPY src/cls/ /tmp/cls/
COPY src/python/ /opt/iris/python/src/
RUN mkdir -p /opt/iris/python/lib

RUN chown -R ${ISC_PACKAGE_MGRUSER}:${ISC_PACKAGE_MGRGROUP} /opt/iris
RUN chown -R ${ISC_PACKAGE_MGRUSER}:${ISC_PACKAGE_MGRGROUP} /tmp
USER ${ISC_PACKAGE_MGRUSER}

RUN iris start IRIS && \
    iris session IRIS < /tmp/irisbuild.script && \
    iris stop IRIS quietly

RUN rm -rf /tmp/*

RUN pip3 install -r /opt/iris/python/src/requirements.txt --target /opt/iris/python/lib
ENV PYTHONPATH="/opt/iris/python/src:/opt/iris/python/lib"
ENV ISC_DATA_DIRECTORY="/persistent/iris"