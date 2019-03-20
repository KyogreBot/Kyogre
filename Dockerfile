FROM python:3.7.2-stretch

# Set working directory
RUN mkdir /src
WORKDIR /src

# Install dumb-init
RUN wget -O /usr/local/bin/dumb-init https://github.com/Yelp/dumb-init/releases/download/v1.2.1/dumb-init_1.2.1_amd64
RUN chmod +x /usr/local/bin/dumb-init

# Install requirements
COPY ./requirements.txt /src/
RUN pip install -r /src/requirements.txt
RUN pip install --user https://github.com/rogerbinns/apsw/releases/download/3.27.2-r1/apsw-3.27.2-r1.zip \
--global-option=fetch --global-option=--version --global-option=3.27.2 --global-option=--all \
--global-option=build --global-option=--enable-all-extensions

# Install discord module
RUN python3 -m pip install -U git+https://github.com/Rapptz/discord.py@rewrite

# Bundle app source
ADD . /src

# Set default container command
ENTRYPOINT ["dumb-init", "--", "python", "-m", "meowth", "launcher"]
