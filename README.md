# Kyogre

A Discord helper bot for Pokemon Go communities.

Kyogre is a heavily modified fork of [Meowth (discordpy-v1 branch)](https://github.com/FoglyOgly/Meowth/tree/discordpy-v1), a Discord bot written in Python 3.6.1+ built with [discord.py v1.0.0a (rewrite branch)](https://github.com/Rapptz/discord.py/tree/rewrite)

## Kyogre Features

Kyogre assists with organising Pokemon Go communities with support for:

 - Team assignments
 - Server greetings
 - Wild Pokemon reporting
 - Raid reporting and RSVP
 - Research reporting
 - Pokebattler integration for raid counters
 - Silph card integration
 - Gym matching
 - Regional subdividing for large servers
 - Notification subscriptions
 - Automated listings for raids, research, wilds, etc
 - Nest reporting (coming soon)

### -- IMPORTANT NOTE -- The following installation/usage instructions are from the Meowth repo linked above. However, PLEASE do not contact the Meowth team for support regarding this bot's features. We have implemented functionality they do not support, hence the rename.

## Dependencies

## **`Python 3.6.1+`**

[Go here](https://github.com/FoglyOgly/Meowth#installing-python) for details on how to install Python 3.6.

**For all future CLI commands, replace the command name `python3` with the relevant interpreter command name for your system (such as the common `py` command name on Windows). See details [here](https://github.com/FoglyOgly/Meowth#installing-python).**

## **`Discord.py v1.0.0a (Rewrite Branch)`**

The [rewrite branch of discord.py](https://github.com/Rapptz/discord.py/tree/rewrite) is an in-development branch that does not yet have an official stable release, however the default/master branch is feature-frozen, and lacks support for some of the newer features in discord such as categories.

If you intend to fork Meowth and alter any code, ensure you keep up to date with any breaking changes that might occur in this branch of discord.py.

```bash
python3 -m pip install -U git+https://github.com/Rapptz/discord.py@rewrite
```

#### *``Note: You will receive the following warning on your first run, which can be disregarded:``*
`PyNaCl is not installed, voice will NOT be supported`

## **`Git`**

To clone the files from our repository or your own forked repository on GitHub, you will need to have `git` installed.

### Windows

Download the [Git for Windows](https://git-scm.com/download/win) software.

On install, ensure the following:
 - `Windows Explorer integration` component (and all sub-components) is selected.
 - `Use Git from the Windows Command Prompt` is selected in the PATH adjustment step.
 - `Checkout as-is, commit Unix-style line endings` is selected in the line ending config step.
 
 ### Linux

First check if it's already installed with:
```bash
git --version
```

If it's not already installed, use your relevant package manager to install it.

For Debian and Ubuntu, it would usually be:
```bash
sudo apt-get install git
```

## **`Required Python Packages`**

Linux:
```bash
python3 -m pip install "requests>=2.18.4" "hastebin.py>=0.2" "python-dateutil>=2.6.1" "fuzzywuzzy>=0.15.1" "dateparser>=0.6.0"
```

## **`Optional Python Packages`**

`python-Levenshtein` is an optional package that increases the speed of fuzzy matching strings, which we use for matching up pokemon names, gym names and possibly other things in future. It also removes the `Using slow pure-python SequenceMatcher` warning emitted from the `fuzzywuzzy` python package, which can otherwise be ignored.

```bash
python3 -m pip install python-Levenshtein
```

The above may not be supported on all systems. You can sometimes find a suitable wheel [here](https://www.lfd.uci.edu/~gohlke/pythonlibs/#python-levenshtein) to install with, or you may have to look around for details suitable for your specific system.

## **`Meowth`**

1. Create a Bot user in the [Discord Developers panel](https://discordapp.com/developers/applications/me):
   - Click `New App`
   - Add an App Name, Description and App Icon (which will be intial bot avatar image)
   - Click `Create App`
   - Click `Create a Bot User`
   - Copy down your Client ID in the App Details box at the very top
   - In the App Bot User box, click to reveal Token and copy it down
   - *Optional:* Tick the Public Bot tickbox if you want to allow others to invite your bot to their own server.

1. Download the files in this repository, or your own fork if you intend to modify source  
   #### *``Note: If you alter the code significantly, adapt to support platforms we don't or integrate any TOS-breaking features, we ask you don't name your instance Meowth to avoid confusion to users between our instance and yours.``*

1. Copy the bot config template `config_blank.json`, rename to `config.json` and edit it:
   - `bot_token` is the Token you copied down earlier from the Discord Developers page and requires quotes as it's a string.
   - `default_prefix` is the prefix the bot will use by default until a guild specifies otherwise with the `set prefix` command
   - `master` is your personal discord account ID. This should be a long set of numbers like `174764205927432192` and should not have quotes around it, as it's an `int` not a string.
     * You can get your ID by enabling Developer Mode on the Discord Client, in `User Settings` > `Appearance` > `Advanced`, which then enables you to right-click your username in chat and select the option `Copy ID`
     * Another method is to mention yourself in chat and add `\` directly behind the mention for it to escape the mention string that's created, revealing your ID.
   - `type_id_dict` specifies what Pokemon Type emojis to use for your bot.  
      - By default, it assumes you have the emojis in your own discord guild, and doesn't use the specific external emoji format.  If you intend to allow the bot on multiple guilds, you will want to setup the external emoji strings.

1. Invite your Bot's User to your guild:
   - Get the Client ID you copied earlier from the Discord Developers page and replace the text `<CLIENT_ID>` with it in the following URL:  
   `https://discordapp.com/oauth2/authorize?client_id=<CLIENT_ID>&scope=bot&permissions=268822608`
   - Go to the URL, select your server and click `Authorize`
   - Verify you aren't a robot (if the captcha doesn't appear, disable your adblocker)
  


1. Run the launcher from the command prompt or terminal window:  
   `python3 launcher.py`

   If successful, it should send "Meowth! That's right!" as well as basic info on startup.

1. Simply type `!configure` in your server to start the configuration process as normal.

## Launcher Reference:
### Arguments
```
  --help, -h           Show the help message
  --auto-restart, -r   Auto-Restarts Meowth in case of a crash.
  --debug, -d          Prevents output being sent to Discord DM, as restarting
                       could occur often.
```

### Launch Meowth normally
```bash
python3 launcher.py
```

### Launch Meowth in debug mode if working on code changes
```bash
python3 launcher.py -d
```

### Launch Meowth with Auto-Restart
```bash
python3 launcher.py -r
```

### Running the docker image
```bash
docker build -t kyogre .

docker run -d -i \
--name kyogre \
-v ${CONFIG_FULL_PATH}:/src/config.json \
-v ${DATA_PATH}:/src/data \
kyogre
```