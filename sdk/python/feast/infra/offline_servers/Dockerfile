FROM python:3.11-slim

RUN apt-get update && apt-get install -y git

# Allow statements and log messages to immediately appear in the Knative logs
ENV PYTHONUNBUFFERED True

# Copy local code to the container image.
ENV APP_HOME /app
WORKDIR $APP_HOME

# Copy app handler code
COPY sdk/python/feast/infra/offline_servers/app.py ./app.py

# Copy necessary parts of the Feast codebase
COPY sdk/python ./sdk/python
COPY protos ./protos
COPY setup.py setup.py
COPY pyproject.toml pyproject.toml
COPY README.md ./README.md

# Install production dependencies.
RUN --mount=source=.git,target=.git,type=bind SETUPTOOLS_SCM_PRETEND_VERSION=1  pip3 install --no-cache-dir -e '.[aws,gcp,snowflake,redis,spark,mysql,postgres,trino,azure]'

# Start offline server
CMD [ "python", "app.py" ]
