FROM alpine:3.11
LABEL maintainer="Ian Redden <iaredden@cisco.com>"

# install packages we need
RUN apk update && apk add --no-cache musl-dev openssl-dev gcc python3 py3-configobj python3-dev supervisor git libffi-dev uwsgi-python3 uwsgi-http jq nano

# copy over scripts to init
ADD code /app
ADD scripts /
RUN mv /uwsgi.ini /etc/uwsgi
RUN chmod +x /*.sh

# do the Python dependencies
RUN pip3 install -r /app/requirements.txt
RUN chown -R uwsgi.uwsgi /etc/uwsgi

# entrypoint
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/start.sh"]
