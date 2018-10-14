FROM python:3.7

# Set working directory
RUN mkdir /src
WORKDIR /src

# Install dumb-init
RUN wget -O /usr/local/bin/dumb-init https://github.com/Yelp/dumb-init/releases/download/v1.2.1/dumb-init_1.2.1_amd64
RUN chmod +x /usr/local/bin/dumb-init

# Install requirements
COPY ./requirements.txt /src/
RUN pip install -r /src/requirements.txt

# Install discord module
RUN python3 -m pip install -U git+https://github.com/Rapptz/discord.py@rewrite

# Bundle app source
ADD . /src

# Set default container command
ENTRYPOINT ["dumb-init", "--", "python", "launcher.py"]