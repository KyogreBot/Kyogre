import re

from fuzzywuzzy import fuzz
from fuzzywuzzy import process

import discord
import asyncio

from meowth.exts import pokemon

Pokemon = pokemon.Pokemon

def get_match(word_list: list, word: str, score_cutoff: int = 60, isPartial: bool = False, limit: int = 1):
    """Uses fuzzywuzzy to see if word is close to entries in word_list

    Returns a tuple of (MATCH, SCORE)
    """
    result = None
    scorer = fuzz.ratio
    if isPartial:
        scorer = fuzz.partial_ratio
    if limit == 1:
        result = process.extractOne(word, word_list, 
            scorer=scorer, score_cutoff=score_cutoff)  
    else:
        result = process.extractBests(word, word_list, 
            scorer=scorer, score_cutoff=score_cutoff, limit=limit)
    if not result:
        return (None, None)
    return result

def colour(*args):
    """Returns a discord Colour object.

    Pass one as an argument to define colour:
        `int` match colour value.
        `str` match common colour names.
        `discord.Guild` bot's guild colour.
        `None` light grey.
    """
    arg = args[0] if args else None
    if isinstance(arg, int):
        return discord.Colour(arg)
    if isinstance(arg, str):
        colour = arg
        try:
            return getattr(discord.Colour, colour)()
        except AttributeError:
            return discord.Colour.lighter_grey()
    if isinstance(arg, discord.Guild):
        return arg.me.colour
    else:
        return discord.Colour.lighter_grey()

def make_embed(msg_type='', title=None, icon=None, content=None,
               msg_colour=None, guild=None, title_url=None,
               thumbnail='', image='', fields=None, footer=None,
               footer_icon=None, inline=False):
    """Returns a formatted discord embed object.

    Define either a type or a colour.
    Types are:
    error, warning, info, success, help.
    """

    embed_types = {
        'error':{
            'icon':'https://i.imgur.com/juhq2uJ.png',
            'colour':'red'
        },
        'warning':{
            'icon':'https://i.imgur.com/4JuaNt9.png',
            'colour':'gold'
        },
        'info':{
            'icon':'https://i.imgur.com/wzryVaS.png',
            'colour':'blue'
        },
        'success':{
            'icon':'https://i.imgur.com/ZTKc3mr.png',
            'colour':'green'
        },
        'help':{
            'icon':'https://i.imgur.com/kTTIZzR.png',
            'colour':'blue'
        }
    }
    if msg_type in embed_types.keys():
        msg_colour = embed_types[msg_type]['colour']
        icon = embed_types[msg_type]['icon']
    if guild and not msg_colour:
        msg_colour = colour(guild)
    else:
        if not isinstance(msg_colour, discord.Colour):
            msg_colour = colour(msg_colour)
    embed = discord.Embed(description=content, colour=msg_colour)
    if not title_url:
        title_url = discord.Embed.Empty
    if not icon:
        icon = discord.Embed.Empty
    if title:
        embed.set_author(name=title, icon_url=icon, url=title_url)
    if thumbnail:
        embed.set_thumbnail(url=thumbnail)
    if image:
        embed.set_image(url=image)
    if fields:
        for key, value in fields.items():
            ilf = inline
            if not isinstance(value, str):
                ilf = value[0]
                value = value[1]
            embed.add_field(name=key, value=value, inline=ilf)
    if footer:
        footer = {'text':footer}
        if footer_icon:
            footer['icon_url'] = footer_icon
        embed.set_footer(**footer)
    return embed

def bold(msg: str):
    """Format to bold markdown text"""
    return f'**{msg}**'

def italics(msg: str):
    """Format to italics markdown text"""
    return f'*{msg}*'

def bolditalics(msg: str):
    """Format to bold italics markdown text"""
    return f'***{msg}***'

def code(msg: str):
    """Format to markdown code block"""
    return f'```{msg}```'

def pycode(msg: str):
    """Format to code block with python code highlighting"""
    return f'```py\n{msg}```'

def ilcode(msg: str):
    """Format to inline markdown code"""
    return f'`{msg}`'

def convert_to_bool(argument):
    lowered = argument.lower()
    if lowered in ('yes', 'y', 'true', 't', '1', 'enable', 'on'):
        return True
    elif lowered in ('no', 'n', 'false', 'f', '0', 'disable', 'off'):
        return False
    else:
        return None

def sanitize_channel_name(name):
    """Converts a given string into a compatible discord channel name."""
    # Remove all characters other than alphanumerics,
    # dashes, underscores, and spaces
    ret = re.sub('[^a-zA-Z0-9 _\\-]', '', name)
    # Replace spaces with dashes
    ret = ret.replace(' ', '-')
    return ret

async def get_raid_help(prefix, avatar, user=None):
    helpembed = discord.Embed(colour=discord.Colour.lighter_grey())
    helpembed.set_author(name="Raid Coordination Help", icon_url=avatar)
    helpembed.add_field(
        name="Key",
        value="<> denote required arguments, [] denote optional arguments",
        inline=False)
    helpembed.add_field(
        name="Raid MGMT Commands",
        value=(
            f"`{prefix}raid <species>`\n"
            f"`{prefix}weather <weather>`\n"
            f"`{prefix}timerset <minutes>`\n"
            f"`{prefix}starttime <time>`\n"
            "`<google maps link>`\n"
            "**RSVP**\n"
            f"`{prefix}(i/c/h)...\n"
            "[total]...\n"
            "[team counts]`\n"
            "**Lists**\n"
            f"`{prefix}list [status]`\n"
            f"`{prefix}list [status] tags`\n"
            f"`{prefix}list teams`\n\n"
            f"`{prefix}starting [team]`"))
    helpembed.add_field(
        name="Description",
        value=(
            "`Hatches Egg channel`\n"
            "`Sets in-game weather`\n"
            "`Sets hatch/raid timer`\n"
            "`Sets start time`\n"
            "`Updates raid location`\n\n"
            "`interested/coming/here`\n"
            "`# of trainers`\n"
            "`# from each team (ex. 3m for 3 Mystic)`\n\n"
            "`Lists trainers by status`\n"
            "`@mentions trainers by status`\n"
            "`Lists trainers by team`\n\n"
            "`Moves trainers on 'here' list to a lobby.`"))
    if not user:
        return helpembed
    await user.send(embed=helpembed)

def get_raidlist(bot):
    raidlist = []
    for level in bot.raid_info['raid_eggs']:
        for pokemon in bot.raid_info['raid_eggs'][level]['pokemon']:
            mon = Pokemon.get_pokemon(bot, pokemon)
            raidlist.append(mon.name.lower())
    return raidlist

def get_level(bot, pkmn):
    for level, pkmn_list in bot.raid_info['raid_eggs'].items():
        if pkmn.lower() in pkmn_list["pokemon"]:
            return level

def get_effectiveness(type_eff):
        if type_eff == 1:
            return 1.4
        if type_eff == -1:
            return 0.714
        if type_eff == -2:
            return 0.51
        return 1

async def ask(bot, message, user_list=None, timeout=60, *, react_list=['✅', '❎']):
    if user_list and not isinstance(user_list, list):
        user_list = [user_list]
    def check(reaction, user):
        if user_list and isinstance(user_list, list):
            return (user.id in user_list) and (reaction.message.id == message.id) and (reaction.emoji in react_list)
        elif not user_list:
            return (user.id != message.author.id) and (reaction.message.id == message.id) and (reaction.emoji in react_list)
    for r in react_list:
        await asyncio.sleep(0.25)
        await message.add_reaction(r)
    try:
        reaction, user = await bot.wait_for('reaction_add', check=check, timeout=timeout)
        return reaction, user
    except asyncio.TimeoutError:
        await message.clear_reactions()
        return

async def ask_list(bot, prompt, destination, choices_list, options_emoji_list, user_list=None, *, allow_edit=False):    
    if not (choices_list and options_emoji_list):
        return None    
    next_emoji = '➡'
    next_emoji_text = '➡️'
    edit_emoji = '✏'
    edit_emoji_text = '✏️'
    cancel_emoji = '❌'
    num_pages = (len(choices_list) - 1) // len(options_emoji_list)    
    for offset in range(num_pages + 1):
        list_embed = discord.Embed(colour=destination.guild.me.colour)
        other_options = []
        emojified_options = []
        current_start = offset * len(options_emoji_list)
        current_options_emoji = options_emoji_list
        current_choices = choices_list[current_start:current_start+len(options_emoji_list)]
        try:
            if len(current_choices) < len(current_options_emoji):
                current_options_emoji = current_options_emoji[:len(current_choices)]
            for i, name in enumerate(current_choices):
                emojified_options.append(f"{current_options_emoji[i]}: {name}")
            list_embed.add_field(name=prompt, value='\n'.join(emojified_options), inline=False)
            embed_footer="Choose the reaction corresponding to the desired entry above."
            if offset != num_pages:
                other_options.append(next_emoji)
                embed_footer += f" Select {next_emoji_text} to see more options."
            if allow_edit:
                other_options.append(edit_emoji)
                embed_footer += f" To enter a custom answer, select {edit_emoji_text}."
            embed_footer += f" Select {cancel_emoji} to cancel."
            list_embed.set_footer(text=embed_footer)
            other_options.append(cancel_emoji)
            q_msg = await destination.send(embed=list_embed)
            all_options = current_options_emoji + other_options
            reaction, __ = await ask(bot, q_msg, user_list, react_list=all_options)
        except TypeError:
            return None
        if not reaction:
            return None
        await q_msg.delete()
        if reaction.emoji in current_options_emoji:
            return choices_list[current_start+current_options_emoji.index(reaction.emoji)]
        if reaction.emoji == edit_emoji:
            break
        if reaction.emoji == cancel_emoji:
            return None    
    def check(message):
        if user_list and type(user_list) is __builtins__.list:
            return (message.author.id in user_list)
        elif not user_list:
            return (message.author.id != message.guild.me.id)
        return message.author.id == user_list
    try:
        await destination.send("Meowth! What's the custom value?")
        message = await bot.wait_for('message', check=check, timeout=60)
        return message.content
    except Exception:
        return None