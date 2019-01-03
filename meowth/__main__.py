import asyncio
import copy
import datetime
import errno
import functools
import gettext
import heapq
import io
import itertools
import json
import os
import pickle
import re
import sys
import tempfile
import textwrap
import time
import traceback

from contextlib import redirect_stdout
from io import BytesIO
from operator import itemgetter
from time import strftime

import aiohttp
import dateparser
import hastebin
from dateutil import tz
from dateutil.relativedelta import relativedelta

import discord
from discord.ext import commands

from meowth.exts.db.kyogredb import *
KyogreDB.start('data/kyogre.db')

from meowth import checks, utils, constants
from meowth.bot import MeowthBot
from meowth.errors import custom_error_handling
from meowth.logs import init_loggers
from meowth.exts.pokemon import Pokemon

logger = init_loggers()
_ = gettext.gettext

def _get_prefix(bot, message):
    guild = message.guild
    try:
        prefix = bot.guild_dict[guild.id]['configure_dict']['settings']['prefix']
    except (KeyError, AttributeError):
        prefix = None
    if not prefix:
        prefix = bot.config['default_prefix']
    return commands.when_mentioned_or(prefix)(bot, message)

Meowth = MeowthBot(
    command_prefix=_get_prefix, case_insensitive=True,
    activity=discord.Game(name="Pokemon Go"))

custom_error_handling(Meowth, logger)

def _load_data(bot):
    try:
        with open(os.path.join('data', 'serverdict'), 'rb') as fd:
            bot.guild_dict = pickle.load(fd)
        logger.info('Serverdict Loaded Successfully')
    except OSError:
        logger.info('Serverdict Not Found - Looking for Backup')
        try:
            with open(os.path.join('data', 'serverdict_backup'), 'rb') as fd:
                bot.guild_dict = pickle.load(fd)
            logger.info('Serverdict Backup Loaded Successfully')
        except OSError:
            logger.info('Serverdict Backup Not Found - Creating New Serverdict')
            bot.guild_dict = {}
            with open(os.path.join('data', 'serverdict'), 'wb') as fd:
                pickle.dump(bot.guild_dict, fd, -1)
            logger.info('Serverdict Created')

_load_data(Meowth)

guild_dict = Meowth.guild_dict

config = {}
defense_chart = {}
type_list = []
raid_info = {}

active_raids = []
active_wilds = []

"""
Helper functions
"""

def load_config():
    global config
    global defense_chart
    global type_list
    global raid_info
    # Load configuration
    with open('config.json', 'r') as fd:
        config = json.load(fd)
    # Set up message catalog access
    language = gettext.translation(
        'meowth', localedir='locale', languages=[config['bot-language']])
    language.install()
    # Load raid info
    raid_path_source = os.path.join('data', 'raid_info.json')
    with open(raid_path_source, 'r') as fd:
        raid_info = json.load(fd)
    # Load type information
    with open(os.path.join('data', 'defense_chart.json'), 'r') as fd:
        defense_chart = json.load(fd)
    with open(os.path.join('data', 'type_list.json'), 'r') as fd:
        type_list = json.load(fd)
    return raid_path_source

raid_path = load_config()

Meowth.raid_info = raid_info
Meowth.type_list = type_list
Meowth.defense_chart = defense_chart

Meowth.config = config
Meowth.raid_json_path = raid_path

default_exts = ['raiddatahandler', 'tutorial', 'silph', 'utilities', 'pokemon', 'trade', 'locationmatching']

for ext in default_exts:
    try:
        Meowth.load_extension(f"meowth.exts.{ext}")
    except Exception as e:
        print(f'**Error when loading extension {ext}:**\n{type(e).__name__}: {e}')
    else:
        if 'debug' in sys.argv[1:]:
            print(f'Loaded {ext} extension.')

@Meowth.command(name='load')
@checks.is_owner()
async def _load(ctx, *extensions):
    for ext in extensions:
        try:
            ctx.bot.unload_extension(f"meowth.exts.{ext}")
            ctx.bot.load_extension(f"meowth.exts.{ext}")
        except Exception as e:
            error_title = _('**Error when loading extension')
            await ctx.send(f'{error_title} {ext}:**\n'
                           f'{type(e).__name__}: {e}')
        else:
            await ctx.send(_('**Extension {ext} Loaded.**\n').format(ext=ext))

@Meowth.command(name='unload')
@checks.is_owner()
async def _unload(ctx, *extensions):
    exts = [e for e in extensions if f"exts.{e}" in Meowth.extensions]
    for ext in exts:
        ctx.bot.unload_extension(f"exts.{ext}")
    s = 's' if len(exts) > 1 else ''
    await ctx.send(_("**Extension{plural} {est} unloaded.**\n").format(plural=s, est=', '.join(exts)))

def get_raidlist():
    raidlist = []
    for level in raid_info['raid_eggs']:
        for entry in raid_info['raid_eggs'][level]['pokemon']:
            pokemon = Pokemon.get_pokemon(Meowth, entry)
            raidlist.append(pokemon.id)
            raidlist.append(str(pokemon).lower())
    return raidlist

# Given a list of types, return a
# space-separated string of their type IDs,
# as defined in the type_id_dict
def types_to_str(guild, type_list):
    ret = ''
    for p_type in type_list:
        p_type = p_type.lower()
        x2 = ''
        if p_type[-2:] == 'x2':
            p_type = p_type[:-2]
            x2 = 'x2'
        # Append to string
        ret += (parse_emoji(guild,
                config['type_id_dict'][p_type]) + x2) + ' '
    return ret

# Convert an arbitrary string into something which
# is acceptable as a Discord channel name.

def sanitize_name(name):
    # Remove all characters other than alphanumerics,
    # dashes, underscores, and spaces
    ret = re.sub('[^a-zA-Z0-9 _\\-]', '', name)
    # Replace spaces with dashes
    ret = ret.replace(' ', '-')
    return ret

# Given a string, if it fits the pattern :emoji name:,
# and <emoji_name> is in the server's emoji list, then
# return the string <:emoji name:emoji id>. Otherwise,
# just return the string unmodified.

def parse_emoji(guild, emoji_string):
    if (emoji_string[0] == ':') and (emoji_string[-1] == ':'):
        emoji = discord.utils.get(guild.emojis, name=emoji_string.strip(':'))
        if emoji:
            emoji_string = '<:{0}:{1}>'.format(emoji.name, emoji.id)
    return emoji_string

def print_emoji_name(guild, emoji_string):
    # By default, just print the emoji_string
    ret = ('`' + emoji_string) + '`'
    emoji = parse_emoji(guild, emoji_string)
    # If the string was transformed by the parse_emoji
    # call, then it really was an emoji and we should
    # add the raw string so people know what to write.
    if emoji != emoji_string:
        ret = ((emoji + ' (`') + emoji_string) + '`)'
    return ret

# Given an arbitrary string, create a Google Maps
# query using the configured hints

def create_gmaps_query(details, channel, type="raid"):
    if type == "raid" or type == "egg":
        report = "raid"
    else:
        report = type
    if "/maps" in details and "http" in details:
        mapsindex = details.find('/maps')
        newlocindex = details.rfind('http', 0, mapsindex)
        if newlocindex == -1:
            return
        newlocend = details.find(' ', newlocindex)
        if newlocend == -1:
            newloc = details[newlocindex:]
            return newloc
        else:
            newloc = details[newlocindex:newlocend + 1]
            return newloc
    details_list = details.split()
    #look for lat/long coordinates in the location details. If provided,
    #then channel location hints are not needed in the  maps query
    if re.match (r'^\s*-?\d{1,2}\.?\d*,\s*-?\d{1,3}\.?\d*\s*$', details): #regex looks for lat/long in the format similar to 42.434546, -83.985195.
        return "https://www.google.com/maps/search/?api=1&query={0}".format('+'.join(details_list))
    loc_list = guild_dict[channel.guild.id]['configure_dict'][report]['report_channels'][channel.id].split()
    return 'https://www.google.com/maps/search/?api=1&query={0}+{1}'.format('+'.join(details_list), '+'.join(loc_list))

def do_template(message, author, guild):
    not_found = []

    def template_replace(match):
        if match.group(3):
            if match.group(3) == 'user':
                return '{user}'
            elif match.group(3) == 'server':
                return guild.name
            else:
                return match.group(0)
        if match.group(4):
            emoji = (':' + match.group(4)) + ':'
            return parse_emoji(guild, emoji)
        match_type = match.group(1)
        full_match = match.group(0)
        match = match.group(2)
        if match_type == '<':
            mention_match = re.search('(#|@!?|&)([0-9]+)', match)
            match_type = mention_match.group(1)[0]
            match = mention_match.group(2)
        if match_type == '@':
            member = guild.get_member_named(match)
            if match.isdigit() and (not member):
                member = guild.get_member(match)
            if (not member):
                not_found.append(full_match)
            return member.mention if member else full_match
        elif match_type == '#':
            channel = discord.utils.get(guild.text_channels, name=match)
            if match.isdigit() and (not channel):
                channel = guild.get_channel(match)
            if (not channel):
                not_found.append(full_match)
            return channel.mention if channel else full_match
        elif match_type == '&':
            role = discord.utils.get(guild.roles, name=match)
            if match.isdigit() and (not role):
                role = discord.utils.get(guild.roles, id=int(match))
            if (not role):
                not_found.append(full_match)
            return role.mention if role else full_match
    template_pattern = '(?i){(@|#|&|<)([^{}]+)}|{(user|server)}|<*:([a-zA-Z0-9]+):[0-9]*>*'
    msg = re.sub(template_pattern, template_replace, message)
    return (msg, not_found)

async def ask(message, destination, user_list=None, *, react_list=['✅', '❎']):
    if user_list and not isinstance(user_list, list):
        user_list = [user_list]
    def check(reaction, user):
        if user_list and isinstance(user_list, list):
            return (user.id in user_list) and (reaction.message.id == message.id) and (reaction.emoji in react_list)
        elif not user_list:
            return (user.id != message.guild.me.id) and (reaction.message.id == message.id) and (reaction.emoji in react_list)
    for r in react_list:
        await asyncio.sleep(0.25)
        try:
            await message.add_reaction(r)
        except:
            print(f"couldn't add reaction {r}")
    try:
        reaction, user = await Meowth.wait_for('reaction_add', check=check, timeout=60)
        return reaction, user
    except asyncio.TimeoutError:
        await message.clear_reactions()
        return    

@Meowth.command(name='gym')
async def _gym(ctx, *, name):
    message = ctx.message
    channel = ctx.channel
    guild = ctx.guild
    gyms = get_gyms(guild.id)
    gym = await location_match_prompt(channel, message.author.id, name, gyms)
    if not gym:
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f"No gym found with name '{name}'. Try again using the exact gym name!"))
    else:
        gym_embed = discord.Embed(title=_('Click here for directions to {0}!'.format(gym.name)), url=gym.maps_url, colour=guild.me.colour)
        gym_info = _("**Name:** {name}\n**Region:** {region}\n**Notes:** {notes}").format(name=gym.name, notes="_EX Eligible Gym_" if gym.ex_eligible else "N/A", region=gym.region.title())
        gym_embed.add_field(name=_('**Gym Information**'), value=gym_info, inline=False)
        return await channel.send(content="", embed=gym_embed)

def get_gyms(guild_id, regions=None):
    location_matching_cog = Meowth.cogs.get('LocationMatching')
    if not location_matching_cog:
        return None
    gyms = location_matching_cog.get_gyms(guild_id, regions)
    return gyms

def get_stops(guild_id, regions=None):
    location_matching_cog = Meowth.cogs.get('LocationMatching')
    if not location_matching_cog:
        return None
    stops = location_matching_cog.get_stops(guild_id, regions)
    return stops

def get_all_locations(guild_id, regions=None):
    location_matching_cog = Meowth.cogs.get('LocationMatching')
    if not location_matching_cog:
        return None
    stops = location_matching_cog.get_all(guild_id, regions)
    return stops

async def location_match_prompt(channel, author_id, name, locations):
    # note: the following logic assumes json constraints -- no duplicates in source data
    location_matching_cog = Meowth.cogs.get('LocationMatching')
    match = None
    result = location_matching_cog.location_match(name, locations)
    results = [(match.name, score) for match, score in result]
    match = await prompt_match_result(channel, author_id, name, results)
    return next((l for l in locations if l.name == match), None)

async def prompt_match_result(channel, author_id, target, result_list):
    if not isinstance(result_list, list):
        result_list = [result_list]
    if not result_list or result_list[0] is None:
        return None
    # quick check if a full match exists
    exact_match = [match for match, score in result_list if match.lower() == target.lower()]
    if len(exact_match) == 1:
        return exact_match[0]
    # reminder: partial, exact matches have 100 score, that's why this check exists
    perfect_scores = [match for match, score in result_list if score == 100]
    if len(perfect_scores) != 1:
        # one or more imperfect candidates only, ask user which to use
        sorted_result = sorted(result_list, key=lambda t: t[1], reverse=True)
        choices_list = [match for match, score in sorted_result]
        prompt = _("Didn't find an exact match for '{0}'. {1} potential matches found.").format(target, len(result_list))
        match = await utils.ask_list(Meowth, prompt, channel, choices_list, user_list=author_id)
    else:
        # found a solitary best match
        match = perfect_scores[0]
    return match

async def letter_case(iterable, find, *, limits=None):
    servercase_list = []
    lowercase_list = []
    for item in iterable:
        if not item.name:
            continue
        elif item.name and (not limits or item.name.lower() in limits):
            servercase_list.append(item.name)
            lowercase_list.append(item.name.lower())
    if find.lower() in lowercase_list:
        index = lowercase_list.index(find.lower())
        return servercase_list[index]
    else:
        return None

def get_category(channel, level, category_type="raid"):
    guild = channel.guild
    if category_type == "raid" or category_type == "egg":
        report = "raid"
    else:
        report = category_type
    catsort = guild_dict[guild.id]['configure_dict'][report].get('categories', None)
    if catsort == "same":
        return channel.category
    elif catsort == "region":
        category = discord.utils.get(guild.categories,id=guild_dict[guild.id]['configure_dict'][report]['category_dict'][channel.id])
        return category
    elif catsort == "level":
        category = discord.utils.get(guild.categories,id=guild_dict[guild.id]['configure_dict'][report]['category_dict'][level])
        return category
    else:
        return None

def get_raidtext(type, pkmn, level, member, channel):
    if type == "raid":
        raidtext = _("{pkmn} raid reported by {member} in {channel}! Coordinate here!\n\nFor help, react to this message with the question mark and I will DM you a list of commands you can use!").format(pkmn=pkmn.title(), member=member.display_name, channel=channel.mention)
    elif type == "egg":
        raidtext = _("Level {level} raid egg reported by {member} in {channel}! Coordinate here!\n\nFor help, react to this message with the question mark and I will DM you a list of commands you can use!").format(level=level, member=member.display_name, channel=channel.mention)
    elif type == "exraid":
        raidtext = _("EX raid reported by {member} in {channel}! Coordinate here!\n\nFor help, react to this message with the question mark and I will DM you a list of commands you can use!").format(member=member.display_name, channel=channel.mention)
    return raidtext

async def create_raid_channel(raid_type, pkmn, level, details, report_channel):
    guild = report_channel.guild
    cat = None
    if raid_type == "exraid":
        name = _("ex-raid-egg-")
        raid_channel_overwrite_list = report_channel.overwrites
        if guild_dict[guild.id]['configure_dict']['invite']['enabled']:
            if guild_dict[guild.id]['configure_dict']['exraid']['permissions'] == "everyone":
                everyone_overwrite = (guild.default_role, discord.PermissionOverwrite(send_messages=False))
                raid_channel_overwrite_list.append(everyone_overwrite)
            for overwrite in raid_channel_overwrite_list:
                if isinstance(overwrite[0], discord.Role):
                    if overwrite[0].permissions.manage_guild or overwrite[0].permissions.manage_channels or overwrite[0].permissions.manage_messages:
                        continue
                    overwrite[1].send_messages = False
                elif isinstance(overwrite[0], discord.Member):
                    if report_channel.permissions_for(overwrite[0]).manage_guild or report_channel.permissions_for(overwrite[0]).manage_channels or report_channel.permissions_for(overwrite[0]).manage_messages:
                        continue
                    overwrite[1].send_messages = False
                if (overwrite[0].name not in guild.me.top_role.name) and (overwrite[0].name not in guild.me.name):
                    overwrite[1].send_messages = False
            for role in guild.role_hierarchy:
                if role.permissions.manage_guild or role.permissions.manage_channels or role.permissions.manage_messages:
                    raid_channel_overwrite_list.append((role, discord.PermissionOverwrite(send_messages=True)))
        else:
            if guild_dict[guild.id]['configure_dict']['exraid']['permissions'] == "everyone":
                everyone_overwrite = (guild.default_role, discord.PermissionOverwrite(send_messages=True))
                raid_channel_overwrite_list.append(everyone_overwrite)
        cat = get_category(report_channel, "EX", category_type=raid_type)
    elif raid_type == "raid":
        name = pkmn.name.lower() + "_"
        raid_channel_overwrite_list = report_channel.overwrites
        cat = get_category(report_channel, str(pkmn.raid_level), category_type=raid_type)
    elif raid_type == "egg":
        name = _("{level}-egg_").format(level=str(level))
        raid_channel_overwrite_list = report_channel.overwrites
        cat = get_category(report_channel, str(level), category_type=raid_type)
    meowth_overwrite = (Meowth.user, discord.PermissionOverwrite(send_messages=True, read_messages=True, manage_roles=True, manage_channels=True, manage_messages=True, add_reactions=True, external_emojis=True, read_message_history=True, embed_links=True, mention_everyone=True, attach_files=True))
    raid_channel_overwrite_list.append(meowth_overwrite)
    enabled = raid_channels_enabled(guild, report_channel)
    if not enabled:
        user_overwrite = (guild.default_role, discord.PermissionOverwrite(send_messages=False, read_messages=False, read_message_history=False))
        raid_channel_overwrite_list.append(user_overwrite)
    name = sanitize_name(name+details)
    ow = dict(raid_channel_overwrite_list)
    return await guild.create_text_channel(name, overwrites=ow, category=cat)

def raid_channels_enabled(guild, channel):
    enabled = True
    regions = _get_channel_regions(channel, 'raid')
    # TODO: modify this to accomodate multiple regions once necessary
    if regions and len(regions) > 0:
        enabled_dict = guild_dict[guild.id]['configure_dict']['raid'].setdefault('raid_channels', {})
        enabled = enabled_dict.setdefault(regions[0], True)
    return enabled

@Meowth.command(hidden=True)
async def template(ctx, *, sample_message):
    """Sample template messages to see how they would appear."""
    embed = None
    (msg, errors) = do_template(sample_message, ctx.author, ctx.guild)
    if errors:
        if msg.startswith('[') and msg.endswith(']'):
            embed = discord.Embed(
                colour=ctx.guild.me.colour, description=msg[1:-1])
            embed.add_field(name=_('Warning'), value=_('The following could not be found:\n{}').format(
                '\n'.join(errors)))
            await ctx.channel.send(embed=embed)
        else:
            msg = _('{}\n\n**Warning:**\nThe following could not be found: {}').format(
                msg, ', '.join(errors))
            await ctx.channel.send(msg)
    elif msg.startswith('[') and msg.endswith(']'):
        await ctx.channel.send(embed=discord.Embed(colour=ctx.guild.me.colour, description=msg[1:-1].format(user=ctx.author.mention)))
    else:
        await ctx.channel.send(msg.format(user=ctx.author.mention))

"""
Server Management
"""

async def wild_expiry_check(message):
    logger.info('Expiry_Check - ' + message.channel.name)
    guild = message.channel.guild
    global active_wilds
    message = await message.channel.get_message(message.id)
    if message not in active_wilds:
        active_wilds.append(message)
        logger.info(
        'wild_expiry_check - Message added to watchlist - ' + message.channel.name
        )
        await asyncio.sleep(0.5)
        while True:
            try:
                if guild_dict[guild.id]['wildreport_dict'][message.id]['exp'] <= time.time():
                    await expire_wild(message)
            except KeyError:
                pass
            await asyncio.sleep(30)
            continue

async def expire_wild(message):
    guild = message.channel.guild
    channel = message.channel
    wild_dict = guild_dict[guild.id]['wildreport_dict']
    try:
        await message.edit(embed=discord.Embed(description=guild_dict[guild.id]['wildreport_dict'][message.id]['expedit']['embedcontent'], colour=message.embeds[0].colour.value))
        await message.clear_reactions()
    except discord.errors.NotFound:
        pass
    try:
        user_message = await channel.get_message(wild_dict[message.id]['reportmessage'])
        await user_message.delete()
    except (discord.errors.NotFound, discord.errors.Forbidden, discord.errors.HTTPException):
        pass
    del guild_dict[guild.id]['wildreport_dict'][message.id]
    await _update_listing_channels(guild, 'wild', edit=True, regions=_get_channel_regions(channel, 'wild'))

async def expiry_check(channel):
    logger.info('Expiry_Check - ' + channel.name)
    guild = channel.guild
    global active_raids
    channel = Meowth.get_channel(channel.id)
    if channel not in active_raids:
        active_raids.append(channel)
        logger.info(
            'Expire_Channel - Channel Added To Watchlist - ' + channel.name)
        await asyncio.sleep(0.5)
        while True:
            try:
                if guild_dict[guild.id]['raidchannel_dict'][channel.id].get('meetup',{}):
                    now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])
                    start = guild_dict[guild.id]['raidchannel_dict'][channel.id]['meetup'].get('start',False)
                    end = guild_dict[guild.id]['raidchannel_dict'][channel.id]['meetup'].get('end',False)
                    if start and guild_dict[guild.id]['raidchannel_dict'][channel.id]['type'] == 'egg':
                        if start < now:
                            pokemon = raid_info['raid_eggs']['EX']['pokemon'][0]
                            await _eggtoraid(pokemon, channel, author=None)
                    if end and end < now:
                        event_loop.create_task(expire_channel(channel))
                        try:
                            active_raids.remove(channel)
                        except ValueError:
                            logger.info(
                                'Expire_Channel - Channel Removal From Active Raid Failed - Not in List - ' + channel.name)
                        logger.info(
                            'Expire_Channel - Channel Expired And Removed From Watchlist - ' + channel.name)
                        break
                elif guild_dict[guild.id]['raidchannel_dict'][channel.id]['active']:
                    if guild_dict[guild.id]['raidchannel_dict'][channel.id]['exp']:
                        if guild_dict[guild.id]['raidchannel_dict'][channel.id]['exp'] <= time.time():
                            if guild_dict[guild.id]['raidchannel_dict'][channel.id]['type'] == 'egg':
                                pokemon = guild_dict[guild.id]['raidchannel_dict'][channel.id]['pokemon']
                                egglevel = guild_dict[guild.id]['raidchannel_dict'][channel.id]['egglevel']
                                if not pokemon and len(raid_info['raid_eggs'][egglevel]['pokemon']) == 1:
                                    pokemon = raid_info['raid_eggs'][egglevel]['pokemon'][0]
                                elif not pokemon and egglevel == "5" and guild_dict[channel.guild.id]['configure_dict']['settings'].get('regional','').lower() in raid_info['raid_eggs']["5"]['pokemon']:
                                    pokemon = str(Pokemon.get_pokemon(Meowth, guild_dict[channel.guild.id]['configure_dict']['settings']['regional']))
                                if pokemon:
                                    logger.info(
                                        'Expire_Channel - Egg Auto Hatched - ' + channel.name)
                                    try:
                                        active_raids.remove(channel)
                                    except ValueError:
                                        logger.info(
                                            'Expire_Channel - Channel Removal From Active Raid Failed - Not in List - ' + channel.name)
                                    await _eggtoraid(pokemon.lower(), channel, author=None)
                                    break
                            event_loop.create_task(expire_channel(channel))
                            try:
                                active_raids.remove(channel)
                            except ValueError:
                                logger.info(
                                    'Expire_Channel - Channel Removal From Active Raid Failed - Not in List - ' + channel.name)
                            logger.info(
                                'Expire_Channel - Channel Expired And Removed From Watchlist - ' + channel.name)
                            break
            except:
                pass
            await asyncio.sleep(30)
            continue

async def expire_channel(channel):
    guild = channel.guild
    alreadyexpired = False
    logger.info('Expire_Channel - ' + channel.name)
    # If the channel exists, get ready to delete it.
    # Otherwise, just clean up the dict since someone
    # else deleted the actual channel at some point.
    channel_exists = Meowth.get_channel(channel.id)
    channel = channel_exists
    if (channel_exists == None) and (not Meowth.is_closed()):
        try:
            del guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]
        except KeyError:
            pass
        return
    elif (channel_exists):
        dupechannel = False
        if guild_dict[guild.id]['raidchannel_dict'][channel.id]['active'] == False:
            alreadyexpired = True
        else:
            guild_dict[guild.id]['raidchannel_dict'][channel.id]['active'] = False
        logger.info('Expire_Channel - Channel Expired - ' + channel.name)
        dupecount = guild_dict[guild.id]['raidchannel_dict'][channel.id].get('duplicate',0)
        if dupecount >= 3:
            dupechannel = True
            guild_dict[guild.id]['raidchannel_dict'][channel.id]['duplicate'] = 0
            guild_dict[guild.id]['raidchannel_dict'][channel.id]['exp'] = time.time()
            if (not alreadyexpired):
                await channel.send(_('This channel has been successfully reported as a duplicate and will be deleted in 1 minute. Check the channel list for the other raid channel to coordinate in!\nIf this was in error, reset the raid with **!timerset**'))
            delete_time = (guild_dict[guild.id]['raidchannel_dict'][channel.id]['exp'] + (1 * 60)) - time.time()
        elif guild_dict[guild.id]['raidchannel_dict'][channel.id]['type'] == 'egg' and not guild_dict[guild.id]['raidchannel_dict'][channel.id].get('meetup',{}):
            if (not alreadyexpired):
                pkmn = guild_dict[guild.id]['raidchannel_dict'][channel.id].get('pokemon', None)
                if pkmn:
                    await _eggtoraid(pkmn, channel)
                    return
                maybe_list = []
                trainer_dict = copy.deepcopy(
                    guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['trainer_dict'])
                for trainer in trainer_dict.keys():
                    if trainer_dict[trainer]['status']['maybe']:
                        user = channel.guild.get_member(trainer)
                        maybe_list.append(user.mention)
                h = _('hatched-')
                new_name = h if h not in channel.name else ''
                new_name += channel.name
                await channel.edit(name=new_name)
                await channel.send(_("**This egg has hatched!**\n\n...or the time has just expired. Trainers {trainer_list}: Update the raid to the pokemon that hatched using **!raid <pokemon>** or reset the hatch timer with **!timerset**. This channel will be deactivated until I get an update and I'll delete it in 45 minutes if I don't hear anything.").format(trainer_list=', '.join(maybe_list)))
            delete_time = (guild_dict[guild.id]['raidchannel_dict'][channel.id]['exp'] + (45 * 60)) - time.time()
            expiremsg = _('**This level {level} raid egg has expired!**').format(
                level=guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['egglevel'])
        else:
            if (not alreadyexpired):
                e = _('expired-')
                new_name = e if e not in channel.name else ''
                new_name += channel.name
                await channel.edit(name=new_name)
                await channel.send(_('This channel timer has expired! The channel has been deactivated and will be deleted in 1 minute.\nTo reactivate the channel, use **!timerset** to set the timer again.'))
            delete_time = (guild_dict[guild.id]['raidchannel_dict'][channel.id]['exp'] + (1 * 60)) - time.time()
            raidtype = _("event") if guild_dict[guild.id]['raidchannel_dict'][channel.id].get('meetup',False) else _(" raid")
            expiremsg = _('**This {pokemon}{raidtype} has expired!**').format(
                pokemon=guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['pokemon'].capitalize(), raidtype=raidtype)
        await asyncio.sleep(delete_time)
        # If the channel has already been deleted from the dict, someone
        # else got to it before us, so don't do anything.
        # Also, if the channel got reactivated, don't do anything either.
        try:
            if (not guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['active']) and (not Meowth.is_closed()):
                if dupechannel:
                    try:
                        report_channel = Meowth.get_channel(
                            guild_dict[guild.id]['raidchannel_dict'][channel.id]['reportcity'])
                        reportmsg = await report_channel.get_message(guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['raidreport'])
                        await reportmsg.delete()
                    except:
                        pass
                else:
                    try:
                        report_channel = Meowth.get_channel(
                            guild_dict[guild.id]['raidchannel_dict'][channel.id]['reportcity'])
                        reportmsg = await report_channel.get_message(guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['raidreport'])
                        await reportmsg.edit(embed=discord.Embed(description=expiremsg, colour=channel.guild.me.colour))
                        await reportmsg.clear_reactions()
                        await _update_listing_channels(guild, 'raid', edit=True, regions=guild_dict[guild.id]['raidchannel_dict'][channel.id].get('regions', None))
                    except:
                        pass
                    # channel doesn't exist anymore in serverdict
                archive = guild_dict[guild.id]['raidchannel_dict'][channel.id].get('archive',False)
                logs = guild_dict[channel.guild.id]['raidchannel_dict'][channel.id].get('logs', {})
                channel_exists = Meowth.get_channel(channel.id)
                if channel_exists == None:
                    return
                elif not archive and not logs:
                    try:
                        del guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]
                    except KeyError:
                        pass
                    await channel_exists.delete()
                    logger.info(
                        'Expire_Channel - Channel Deleted - ' + channel.name)
                elif archive or logs:
                    try:
                        for overwrite in channel.overwrites:
                            if isinstance(overwrite[0], discord.Role):
                                if overwrite[0].permissions.manage_guild or overwrite[0].permissions.manage_channels:
                                    await channel.set_permissions(overwrite[0], read_messages=True)
                                    continue
                            elif isinstance(overwrite[0], discord.Member):
                                if channel.permissions_for(overwrite[0]).manage_guild or channel.permissions_for(overwrite[0]).manage_channels:
                                    await channel.set_permissions(overwrite[0], read_messages=True)
                                    continue
                            if (overwrite[0].name not in guild.me.top_role.name) and (overwrite[0].name not in guild.me.name):
                                await channel.set_permissions(overwrite[0], read_messages=False)
                        for role in guild.role_hierarchy:
                            if role.permissions.manage_guild or role.permissions.manage_channels:
                                await channel.set_permissions(role, read_messages=True)
                            continue
                        await channel.set_permissions(guild.default_role, read_messages=False)
                    except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
                        pass
                    new_name = _('archived-')
                    if new_name not in channel.name:
                        new_name += channel.name
                        category = guild_dict[channel.guild.id]['configure_dict'].get('archive', {}).get('category', 'same')
                        if category == 'same':
                            newcat = channel.category
                        else:
                            newcat = channel.guild.get_channel(category)
                        await channel.edit(name=new_name, category=newcat)
                        await channel.send(_('-----------------------------------------------\n**The channel has been archived and removed from view for everybody but Kyogre and those with Manage Channel permissions. Any messages that were deleted after the channel was marked for archival will be posted below. You will need to delete this channel manually.**\n-----------------------------------------------'))
                        while logs:
                            earliest = min(logs)
                            embed = discord.Embed(colour=logs[earliest]['color_int'], description=logs[earliest]['content'], timestamp=logs[earliest]['created_at'])
                            if logs[earliest]['author_nick']:
                                embed.set_author(name="{name} [{nick}]".format(name=logs[earliest]['author_str'],nick=logs[earliest]['author_nick']), icon_url = logs[earliest]['author_avy'])
                            else:
                                embed.set_author(name=logs[earliest]['author_str'], icon_url = logs[earliest]['author_avy'])
                            await channel.send(embed=embed)
                            del logs[earliest]
                            await asyncio.sleep(.25)
                        del guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]
        except:
            pass

Meowth.expire_channel = expire_channel

async def channel_cleanup(loop=True):
    while (not Meowth.is_closed()):
        global active_raids
        guilddict_chtemp = copy.deepcopy(guild_dict)
        logger.info('Channel_Cleanup ------ BEGIN ------')
        # for every server in save data
        for guildid in guilddict_chtemp.keys():
            guild = Meowth.get_guild(guildid)
            log_str = 'Channel_Cleanup - Server: ' + str(guildid)
            log_str = log_str + ' - CHECKING FOR SERVER'
            if guild == None:
                logger.info(log_str + ': NOT FOUND')
                continue
            logger.info(((log_str + ' (') + guild.name) +
                        ')  - BEGIN CHECKING SERVER')
            # clear channel lists
            dict_channel_delete = []
            discord_channel_delete = []
            # check every raid channel data for each server
            for channelid in guilddict_chtemp[guildid]['raidchannel_dict']:
                channel = Meowth.get_channel(channelid)
                log_str = 'Channel_Cleanup - Server: ' + guild.name
                log_str = (log_str + ': Channel:') + str(channelid)
                logger.info(log_str + ' - CHECKING')
                channelmatch = Meowth.get_channel(channelid)
                if channelmatch == None:
                    # list channel for deletion from save data
                    dict_channel_delete.append(channelid)
                    logger.info(log_str + " - NOT IN DISCORD")
                # otherwise, if meowth can still see the channel in discord
                else:
                    logger.info(
                        ((log_str + ' (') + channel.name) + ') - EXISTS IN DISCORD')
                    # if the channel save data shows it's not an active raid
                    if guilddict_chtemp[guildid]['raidchannel_dict'][channelid]['active'] == False:
                        if guilddict_chtemp[guildid]['raidchannel_dict'][channelid]['type'] == 'egg':
                            # and if it has been expired for longer than 45 minutes already
                            if guilddict_chtemp[guildid]['raidchannel_dict'][channelid]['exp'] < (time.time() - (45 * 60)):
                                # list the channel to be removed from save data
                                dict_channel_delete.append(channelid)
                                # and list the channel to be deleted in discord
                                discord_channel_delete.append(channel)
                                logger.info(
                                    log_str + ' - 15+ MIN EXPIRY NONACTIVE EGG')
                                continue
                            # and if it has been expired for longer than 1 minute already
                        elif guilddict_chtemp[guildid]['raidchannel_dict'][channelid]['exp'] < (time.time() - (1 * 60)):
                                # list the channel to be removed from save data
                            dict_channel_delete.append(channelid)
                                # and list the channel to be deleted in discord
                            discord_channel_delete.append(channel)
                            logger.info(
                                log_str + ' - 5+ MIN EXPIRY NONACTIVE RAID')
                            continue
                        event_loop.create_task(expire_channel(channel))
                        logger.info(
                            log_str + ' - = RECENTLY EXPIRED NONACTIVE RAID')
                        continue
                    # if the channel save data shows it as an active raid still
                    elif guilddict_chtemp[guildid]['raidchannel_dict'][channelid]['active'] == True:
                        # if it's an exraid
                        if guilddict_chtemp[guildid]['raidchannel_dict'][channelid]['type'] == 'exraid':
                            logger.info(log_str + ' - EXRAID')

                            continue
                        # or if the expiry time for the channel has already passed within 5 minutes
                        elif guilddict_chtemp[guildid]['raidchannel_dict'][channelid]['exp'] <= time.time():
                            # list the channel to be sent to the channel expiry function
                            event_loop.create_task(expire_channel(channel))
                            logger.info(log_str + ' - RECENTLY EXPIRED')

                            continue

                        if channel not in active_raids:
                            # if channel is still active, make sure it's expiry is being monitored
                            event_loop.create_task(expiry_check(channel))
                            logger.info(
                                log_str + ' - MISSING FROM EXPIRY CHECK')
                            continue
            # for every channel listed to have save data deleted
            for c in dict_channel_delete:
                try:
                    # attempt to delete the channel from save data
                    del guild_dict[guildid]['raidchannel_dict'][c]
                    logger.info(
                        'Channel_Cleanup - Channel Savedata Cleared - ' + str(c))
                except KeyError:
                    pass
            # for every channel listed to have the discord channel deleted
            for c in discord_channel_delete:
                try:
                    # delete channel from discord
                    await c.delete()
                    logger.info(
                        'Channel_Cleanup - Channel Deleted - ' + c.name)
                except:
                    logger.info(
                        'Channel_Cleanup - Channel Deletion Failure - ' + c.name)
                    pass
        # save server_dict changes after cleanup
        logger.info('Channel_Cleanup - SAVING CHANGES')
        try:
            await _save()
        except Exception as err:
            logger.info('Channel_Cleanup - SAVING FAILED' + err)
        logger.info('Channel_Cleanup ------ END ------')
        await asyncio.sleep(600)
        continue

async def guild_cleanup(loop=True):
    while (not Meowth.is_closed()):
        guilddict_srvtemp = copy.deepcopy(guild_dict)
        logger.info('Server_Cleanup ------ BEGIN ------')
        guilddict_srvtemp = guild_dict
        dict_guild_list = []
        bot_guild_list = []
        dict_guild_delete = []
        for guildid in guilddict_srvtemp.keys():
            dict_guild_list.append(guildid)
        for guild in Meowth.guilds:
            bot_guild_list.append(guild.id)
        guild_diff = set(dict_guild_list) - set(bot_guild_list)
        for s in guild_diff:
            dict_guild_delete.append(s)
        for s in dict_guild_delete:
            try:
                del guild_dict[s]
                logger.info(('Server_Cleanup - Cleared ' + str(s)) +
                            ' from save data')
            except KeyError:
                pass
        logger.info('Server_Cleanup - SAVING CHANGES')
        try:
            await _save()
        except Exception as err:
            logger.info('Server_Cleanup - SAVING FAILED' + err)
        logger.info('Server_Cleanup ------ END ------')
        await asyncio.sleep(7200)
        continue

async def message_cleanup(loop=True):
    while (not Meowth.is_closed()):
        logger.info('message_cleanup ------ BEGIN ------')
        guilddict_temp = copy.deepcopy(guild_dict)
        update_ids = set()
        for guildid in guilddict_temp.keys():
            questreport_dict = guilddict_temp[guildid].get('questreport_dict',{})
            wildreport_dict = guilddict_temp[guildid].get('wildreport_dict',{})
            report_dict_dict = {
                'questreport_dict':questreport_dict,
                'wildreport_dict':wildreport_dict,
            }
            report_edit_dict = {}
            report_delete_dict = {}
            for report_dict in report_dict_dict:
                for reportid in report_dict_dict[report_dict].keys():
                    if report_dict_dict[report_dict][reportid].get('exp', 0) <= time.time():
                        report_channel = Meowth.get_channel(report_dict_dict[report_dict][reportid].get('reportchannel'))
                        if report_channel:
                            user_report = report_dict_dict[report_dict][reportid].get('reportmessage',None)
                            if user_report:
                                report_delete_dict[user_report] = {"action":"delete","channel":report_channel}
                            if report_dict_dict[report_dict][reportid].get('expedit') == "delete":
                                report_delete_dict[reportid] = {"action":"delete","channel":report_channel}
                            else:
                                report_edit_dict[reportid] = {"action":report_dict_dict[report_dict][reportid].get('expedit',"edit"),"channel":report_channel}
                        try:
                            del guild_dict[guildid][report_dict][reportid]
                        except KeyError:
                            pass
            for messageid in report_delete_dict.keys():
                try:
                    report_message = await report_delete_dict[messageid]['channel'].get_message(messageid)
                    await report_message.delete()
                    update_ids.add(guildid)
                except (discord.errors.NotFound, discord.errors.Forbidden, discord.errors.HTTPException, KeyError):
                    pass
            for messageid in report_edit_dict.keys():
                try:
                    report_message = await report_edit_dict[messageid]['channel'].get_message(messageid)
                    await report_message.edit(content=report_edit_dict[messageid]['action']['content'],embed=discord.Embed(description=report_edit_dict[messageid]['action'].get('embedcontent'), colour=report_message.embeds[0].colour.value))
                    await report_message.clear_reactions()
                    update_ids.add(guildid)
                except (discord.errors.NotFound, discord.errors.Forbidden, discord.errors.HTTPException, IndexError, KeyError):
                    pass
        # save server_dict changes after cleanup
        for id in update_ids:
            guild = Meowth.get_guild(id)
            await _update_listing_channels(guild, 'wild', edit=True)
            await _update_listing_channels(guild, 'research', edit=True)
        logger.info('message_cleanup - SAVING CHANGES')
        try:
            await _save()
        except Exception as err:
            logger.info('message_cleanup - SAVING FAILED' + err)
        logger.info('message_cleanup ------ END ------')
        await asyncio.sleep(600)
        continue

async def _print(owner, message):
    if 'launcher' in sys.argv[1:]:
        if 'debug' not in sys.argv[1:]:
            await owner.send(message)
    print(message)
    logger.info(message)

async def maint_start():
    tasks = []
    try:
#        event_loop.create_task(guild_cleanup())
        tasks.append(event_loop.create_task(channel_cleanup()))
        tasks.append(event_loop.create_task(message_cleanup()))
        logger.info('Maintenance Tasks Started')
    except KeyboardInterrupt:
        [task.cancel() for task in tasks]

event_loop = asyncio.get_event_loop()

"""
Events
"""
@Meowth.event
async def on_ready():
    Meowth.owner = discord.utils.get(
        Meowth.get_all_members(), id=config['master'])
    await _print(Meowth.owner, _('Starting up...'))
    Meowth.uptime = datetime.datetime.now()
    owners = []
    msg_success = 0
    msg_fail = 0
    guilds = len(Meowth.guilds)
    users = 0
    for guild in Meowth.guilds:
        users += len(guild.members)
        try:
            if guild.id not in guild_dict:
                guild_dict[guild.id] = {
                    'configure_dict':{
                        'welcome': {'enabled':False,'welcomechan':'','welcomemsg':''},
                        'want': {'enabled':False, 'report_channels': []},
                        'raid': {'enabled':False, 'report_channels': {}, 'categories':'same','category_dict':{}},
                        'exraid': {'enabled':False, 'report_channels': {}, 'categories':'same','category_dict':{}, 'permissions':'everyone'},
                        'wild': {'enabled':False, 'report_channels': {}},
                        'counters': {'enabled':False, 'auto_levels': []},
                        'research': {'enabled':False, 'report_channels': {}},
                        'archive': {'enabled':False, 'category':'same','list':None},
                        'invite': {'enabled':False},
                        'team':{'enabled':False},
                        'settings':{'offset':0,'regional':None,'done':False,'prefix':None,'config_sessions':{}}
                    },
                    'wildreport_dict:':{},
                    'questreport_dict':{},
                    'raidchannel_dict':{},
                    'trainers':{}
                }
            else:
                guild_dict[guild.id]['configure_dict'].setdefault('trade', {})
        except KeyError:
            guild_dict[guild.id] = {
                'configure_dict':{
                    'welcome': {'enabled':False,'welcomechan':'','welcomemsg':''},
                    'want': {'enabled':False, 'report_channels': []},
                    'raid': {'enabled':False, 'report_channels': {}, 'categories':'same','category_dict':{}},
                    'exraid': {'enabled':False, 'report_channels': {}, 'categories':'same','category_dict':{}, 'permissions':'everyone'},
                    'counters': {'enabled':False, 'auto_levels': []},
                    'wild': {'enabled':False, 'report_channels': {}},
                    'research': {'enabled':False, 'report_channels': {}},
                    'archive': {'enabled':False, 'category':'same','list':None},
                    'invite': {'enabled':False},
                    'team':{'enabled':False},
                    'settings':{'offset':0,'regional':None,'done':False,'prefix':None,'config_sessions':{}}
                },
                'wildreport_dict:':{},
                'questreport_dict':{},
                'raidchannel_dict':{},
                'trainers':{}
            }
        owners.append(guild.owner)
    await _print(Meowth.owner, _("{server_count} servers connected.\n{member_count} members found.").format(server_count=guilds, member_count=users))
    await maint_start()

@Meowth.event
async def on_guild_join(guild):
    owner = guild.owner
    guild_dict[guild.id] = {
        'configure_dict':{
            'welcome': {'enabled':False,'welcomechan':'','welcomemsg':''},
            'want': {'enabled':False, 'report_channels': []},
            'raid': {'enabled':False, 'report_channels': {}, 'categories':'same','category_dict':{}},
            'exraid': {'enabled':False, 'report_channels': {}, 'categories':'same','category_dict':{}, 'permissions':'everyone'},
            'counters': {'enabled':False, 'auto_levels': []},
            'wild': {'enabled':False, 'report_channels': {}},
            'research': {'enabled':False, 'report_channels': {}},
            'archive': {'enabled':False, 'category':'same','list':None},
            'invite': {'enabled':False},
            'team':{'enabled':False},
            'settings':{'offset':0,'regional':None,'done':False,'prefix':None,'config_sessions':{}}
        },
        'wildreport_dict:':{},
        'questreport_dict':{},
        'raidchannel_dict':{},
        'trainers':{},
        'trade_dict': {}
    }
    await owner.send(_("I'm Kyogre, a Discord helper bot for Pokemon Go communities, and someone has invited me to your server! Type **!help** to see a list of things I can do, and type **!configure** in any channel of your server to begin!"))

@Meowth.event
async def on_guild_remove(guild):
    try:
        if guild.id in guild_dict:
            try:
                del guild_dict[guild.id]
            except KeyError:
                pass
    except KeyError:
        pass

@Meowth.event
async def on_member_join(member):
    'Welcome message to the server and some basic instructions.'
    guild = member.guild
    team_msg = _(' or ').join(['**!team {0}**'.format(team)
                           for team in config['team_dict'].keys()])
    if not guild_dict[guild.id]['configure_dict']['welcome']['enabled']:
        return
    # Build welcome message
    if guild_dict[guild.id]['configure_dict']['welcome'].get('welcomemsg', 'default') == "default":
        admin_message = _(' If you have any questions just ask an admin.')
        welcomemessage = _('Welcome to {server}, {user}! ')
        if guild_dict[guild.id]['configure_dict']['team']['enabled']:
            welcomemessage += _('Set your team by typing {team_command}.').format(
                team_command=team_msg)
        welcomemessage += admin_message
    else:
        welcomemessage = guild_dict[guild.id]['configure_dict']['welcome']['welcomemsg']

    if guild_dict[guild.id]['configure_dict']['welcome']['welcomechan'] == 'dm':
        send_to = member
    elif str(guild_dict[guild.id]['configure_dict']['welcome']['welcomechan']).isdigit():
        send_to = discord.utils.get(guild.text_channels, id=int(guild_dict[guild.id]['configure_dict']['welcome']['welcomechan']))
    else:
        send_to = discord.utils.get(guild.text_channels, name=guild_dict[guild.id]['configure_dict']['welcome']['welcomechan'])
    if send_to:
        if welcomemessage.startswith("[") and welcomemessage.endswith("]"):
            await send_to.send(embed=discord.Embed(colour=guild.me.colour, description=welcomemessage[1:-1].format(server=guild.name, user=member.mention)))
        else:
            await send_to.send(welcomemessage.format(server=guild.name, user=member.mention))
    else:
        return

@Meowth.event
@checks.good_standing()
async def on_message(message):
    # TODO get rid of this garbage, why tf is raid processing here
    if message.guild != None:
        raid_status = guild_dict[message.guild.id]['raidchannel_dict'].get(message.channel.id, None)
        if raid_status:
            if guild_dict[message.guild.id]['configure_dict'].get('archive', {}).get('enabled', False) and guild_dict[message.guild.id]['configure_dict'].get('archive', {}).get('list', []):
                for phrase in guild_dict[message.guild.id]['configure_dict']['archive']['list']:
                    if phrase in message.content:
                        await _archive(message.channel)
            if guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['active']:
                trainer_dict = guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['trainer_dict']
                if message.author.id in trainer_dict:
                    count = trainer_dict[message.author.id].get('count',1)
                else:
                    count = 1
                omw_emoji = parse_emoji(message.guild, config['omw_id'])
                if message.content.startswith(omw_emoji):
                    try:
                        if guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['type'] == 'egg':
                            if guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['pokemon'] == '':
                                await message.channel.send(_("Please wait until the raid egg has hatched before announcing you're coming or present."))
                                return
                    except:
                        pass
                    emoji_count = message.content.count(omw_emoji)
                    await _coming(message.channel, message.author, emoji_count, party=None)
                    return
                here_emoji = parse_emoji(message.guild, config['here_id'])
                if message.content.startswith(here_emoji):
                    try:
                        if guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['type'] == 'egg':
                            if guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['pokemon'] == '':
                                await message.channel.send(_("Please wait until the raid egg has hatched before announcing you're coming or present."))
                                return
                    except:
                        pass
                    emoji_count = message.content.count(here_emoji)
                    await _here(message.channel, message.author, emoji_count, party=None)
                    return
                if "/maps" in message.content and "http" in message.content:
                    newcontent = message.content.replace("<","").replace(">","")
                    newloc = create_gmaps_query(newcontent, message.channel, type=guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['type'])
                    oldraidmsg = await message.channel.get_message(guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['raidmessage'])
                    report_channel = Meowth.get_channel(guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['reportcity'])
                    oldreportmsg = await report_channel.get_message(guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['raidreport'])
                    oldembed = oldraidmsg.embeds[0]
                    newembed = discord.Embed(title=oldembed.title, url=newloc, colour=message.guild.me.colour)
                    for field in oldembed.fields:
                        newembed.add_field(name=field.name, value=field.value, inline=field.inline)
                    newembed.set_footer(text=oldembed.footer.text, icon_url=oldembed.footer.icon_url)
                    newembed.set_thumbnail(url=oldembed.thumbnail.url)
                    try:
                        await oldraidmsg.edit(new_content=oldraidmsg.content, embed=newembed, content=oldraidmsg.content)
                    except:
                        pass
                    try:
                         await oldreportmsg.edit(new_content=oldreportmsg.content, embed=newembed, content=oldreportmsg.content)
                    except:
                        pass
                    guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['raidmessage'] = oldraidmsg.id
                    guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['raidreport'] = oldreportmsg.id
                    otw_list = []
                    trainer_dict = copy.deepcopy(guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['trainer_dict'])
                    for trainer in trainer_dict.keys():
                        if trainer_dict[trainer]['status']['coming']:
                            user = message.guild.get_member(trainer)
                            otw_list.append(user.mention)
                    await message.channel.send(content=_('Someone has suggested a different location for the raid! Trainers {trainer_list}: make sure you are headed to the right place!').format(trainer_list=', '.join(otw_list)), embed=newembed)
                    return
    if (not message.author.bot):
        await Meowth.process_commands(message)

@Meowth.event
async def on_message_delete(message):
    guild = message.guild
    channel = message.channel
    author = message.author
    if not channel or not guild:
        return
    if channel.id in guild_dict[guild.id]['raidchannel_dict'] and guild_dict[guild.id]['configure_dict']['archive']['enabled']:
        if message.content.strip() == "!archive":
            guild_dict[guild.id]['raidchannel_dict'][channel.id]['archive'] = True
        if guild_dict[guild.id]['raidchannel_dict'][channel.id].get('archive', False):
            logs = guild_dict[guild.id]['raidchannel_dict'][channel.id].get('logs', {})
            logs[message.id] = {'author_id': author.id, 'author_str': str(author),'author_avy':author.avatar_url,'author_nick':author.nick,'color_int':author.color.value,'content': message.clean_content,'created_at':message.created_at}
            guild_dict[guild.id]['raidchannel_dict'][channel.id]['logs'] = logs

@Meowth.event
@checks.good_standing()
async def on_raw_reaction_add(payload):
    channel = Meowth.get_channel(payload.channel_id)
    try:
        message = await channel.get_message(payload.message_id)
    except (discord.errors.NotFound, AttributeError):
        return
    guild = message.guild
    try:
        user = guild.get_member(payload.user_id)
    except AttributeError:
        return
    if channel.id in guild_dict[guild.id]['raidchannel_dict'] and user.id != Meowth.user.id:
        if message.id == guild_dict[guild.id]['raidchannel_dict'][channel.id].get('ctrsmessage',None):
            ctrs_dict = guild_dict[guild.id]['raidchannel_dict'][channel.id]['ctrs_dict']
            for i in ctrs_dict:
                if ctrs_dict[i]['emoji'] == str(payload.emoji):
                    newembed = ctrs_dict[i]['embed']
                    moveset = i
                    break
            else:
                return
            await message.edit(embed=newembed)
            guild_dict[guild.id]['raidchannel_dict'][channel.id]['moveset'] = moveset
            await message.remove_reaction(payload.emoji, user)
        elif message.id == guild_dict[guild.id]['raidchannel_dict'][channel.id].get('raidmessage',None):
            if str(payload.emoji) == '\u2754':
                prefix = guild_dict[guild.id]['configure_dict']['settings']['prefix']
                prefix = prefix or Meowth.config['default_prefix']
                avatar = Meowth.user.avatar_url
                await utils.get_raid_help(prefix, avatar, user)
            await message.remove_reaction(payload.emoji, user)
    wildreport_dict = guild_dict[guild.id].setdefault('wildreport_dict', {})
    if message.id in wildreport_dict and user.id != Meowth.user.id:
        wild_dict = guild_dict[guild.id]['wildreport_dict'].get(message.id, None)
        if str(payload.emoji) == '🏎':
            wild_dict['omw'].append(user.mention)
            guild_dict[guild.id]['wildreport_dict'][message.id] = wild_dict
        elif str(payload.emoji) == '💨':
            for reaction in message.reactions:
                if reaction.emoji == '💨' and reaction.count >= 2:
                    if wild_dict['omw']:
                        despawn = _("has despawned")
                        await channel.send(f"{', '.join(wild_dict['omw'])}: {wild_dict['pokemon'].title()} {despawn}!")
                    await expire_wild(message)
    questreport_dict = guild_dict[guild.id].setdefault('questreport_dict', {})
    if message.id in questreport_dict and user.id != Meowth.user.id:
        quest_dict = guild_dict[guild.id]['questreport_dict'].get(message.id, None)        
        if quest_dict and (quest_dict['reportauthor'] == payload.user_id or can_manage(user)):
            if str(payload.emoji) == '\u270f':
                await modify_research_report(payload)
            elif str(payload.emoji) == '🚫':
                try:
                    await message.edit(embed=discord.Embed(description="Research report cancelled", colour=message.embeds[0].colour.value))
                    await message.clear_reactions()
                except discord.errors.NotFound:
                    pass
                del questreport_dict[message.id]
                await _refresh_listing_channels_internal(guild, "research")
    raid_dict = guild_dict[guild.id].setdefault('raidchannel_dict', {})
    raid_report = get_raid_report(guild, message.id)
    if raid_report is not None and user.id != Meowth.user.id:
        if (raid_dict.get(raid_report, {}).get('reporter', 0) == payload.user_id or can_manage(user)):
            if str(payload.emoji) == '\u270f':
                await modify_raid_report(payload, raid_report)
            elif str(payload.emoji) == '🚫':
                try:
                    await message.edit(embed=discord.Embed(description="Raid report cancelled", colour=message.embeds[0].colour.value))
                    await message.clear_reactions()
                except discord.errors.NotFound:
                    pass
                report_channel = Meowth.get_channel(raid_report)
                await report_channel.delete()
                try:
                    del raid_dict[raid_report]
                except:
                    pass
                await _refresh_listing_channels_internal(guild, "raid")

def get_raid_report(guild, message_id):
    raid_dict = guild_dict[guild.id]['raidchannel_dict']
    for raid in raid_dict:
        if raid_dict[raid]['raidreport'] == message_id:
            return raid
    return None

def can_manage(user):
    if checks.is_user_dev_or_owner(config, user.id):
        return True
    for role in user.roles:
        if role.permissions.manage_messages:
            return True
    return False

async def modify_research_report(payload):
    channel = Meowth.get_channel(payload.channel_id)
    try:
        message = await channel.get_message(payload.message_id)
    except (discord.errors.NotFound, AttributeError):
        return
    guild = message.guild
    try:
        user = guild.get_member(payload.user_id)
    except AttributeError:
        return
    questreport_dict = guild_dict[guild.id].setdefault('questreport_dict', {})
    research_embed = discord.Embed(colour=message.guild.me.colour).set_thumbnail(url='https://raw.githubusercontent.com/klords/Kyogre/master/images/misc/field-research.png?cache=0')
    research_embed.set_footer(text=_('Reported by {user}').format(user=user.display_name), icon_url=user.avatar_url_as(format=None, static_format='jpg', size=32))
    config_dict = guild_dict[guild.id]['configure_dict']
    regions = _get_channel_regions(channel, 'research')
    stops = None
    stops = get_stops(guild.id, regions)
    prompt = 'Which item would you like to modify?'
    choices_list = ['Pokestop','Task', 'Reward']
    match = await utils.ask_list(Meowth, prompt, channel, choices_list, user_list=user.id)
    if match in choices_list:
        if match == choices_list[0]:
            query_msg = await channel.send(embed=discord.Embed(colour=discord.Colour.gold(), description="What is the correct Pokestop?"))
            try:
                pokestopmsg = await Meowth.wait_for('message', timeout=30, check=(lambda reply: reply.author == user))
            except asyncio.TimeoutError:
                pokestopmsg = None
                await pokestopmsg.delete()
            if not pokestopmsg:
                error = _("took too long to respond")
            elif pokestopmsg.clean_content.lower() == "cancel":
                error = _("cancelled the report")
                await pokestopmsg.delete()
            elif pokestopmsg:
                if stops:
                    stop = await location_match_prompt(channel, user.id, pokestopmsg.clean_content, stops)
                    if not stop:
                        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f"I couldn't find a pokestop named '{location}'. Try again using the exact pokestop name!"))
                    if get_existing_research(guild, stop):
                        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f"A quest has already been reported for {stop.name}"))
                    location = stop.name
                    loc_url = stop.maps_url
                    questreport_dict[message.id]['location'] = location
                    questreport_dict[message.id]['url'] = loc_url
                    await _refresh_listing_channels_internal(guild, "research")
                    await channel.send(embed=discord.Embed(colour=discord.Colour.green(), description="Research listing updated"))
                    await pokestopmsg.delete()
                    await query_msg.delete()
        elif match == choices_list[1]:
            questwait = await channel.send(embed=discord.Embed(colour=discord.Colour.gold(), description="What is the correct research task?"))
            try:
                questmsg = await Meowth.wait_for('message', timeout=30, check=(lambda reply: reply.author == user))
            except asyncio.TimeoutError:
                questmsg = None
            await questwait.delete()
            if not questmsg:
                error = _("took too long to respond")
            elif questmsg.clean_content.lower() == "cancel":
                error = _("cancelled the report")
                await questmsg.delete()
            elif questmsg:
                quest = await _get_quest_v(channel, user.id, questmsg.clean_content)
                reward = await _prompt_reward_v(channel, user.id, quest)
                if not reward:
                    error = "didn't identify the reward"
            if not quest:
                error = "didn't identify the quest"
            questreport_dict[message.id]['quest'] = quest.name
            questreport_dict[message.id]['reward'] = reward
            await _refresh_listing_channels_internal(guild, "research")
            await channel.send(embed=discord.Embed(colour=discord.Colour.green(), description="Research listing updated"))
            await questmsg.delete()
        elif match == choices_list[2]:
            rewardwait = await channel.send(embed=discord.Embed(colour=discord.Colour.gold(), description="What is the correct reward?"))
            quest = guild_dict[guild.id]['questreport_dict'].get(message.id, None)
            quest = await _get_quest_v(channel, user.id, quest['quest'])
            
            reward = await _prompt_reward_v(channel, user.id, quest)
            if not reward:
                error = "didn't identify the reward"
            questreport_dict[message.id]['reward'] = reward
            await _refresh_listing_channels_internal(guild, "research")
            await channel.send(embed=discord.Embed(colour=discord.Colour.green(), description="Research listing updated"))
            await rewardwait.delete()
        embed = message.embeds[0]
        embed.clear_fields()
        location = questreport_dict[message.id]['location']
        name = questreport_dict[message.id]['quest']
        reward = questreport_dict[message.id]['reward']
        embed.add_field(name=_("**Pokestop:**"),value='\n'.join(textwrap.wrap(location.title(), width=30)),inline=True)
        embed.add_field(name=_("**Quest:**"),value='\n'.join(textwrap.wrap(name.title(), width=30)),inline=True)
        embed.add_field(name=_("**Reward:**"),value='\n'.join(textwrap.wrap(reward.title(), width=30)),inline=True)
        await message.edit(content=message.content,embed=embed)
        await message.clear_reactions()
        await asyncio.sleep(0.25)
        await message.add_reaction('\u270f')
        await asyncio.sleep(0.25)
        await message.add_reaction('🚫')
        await asyncio.sleep(0.25)
    else:
        return

async def modify_raid_report(payload, raid_report):
    channel = Meowth.get_channel(payload.channel_id)
    try:
        message = await channel.get_message(payload.message_id)
    except (discord.errors.NotFound, AttributeError):
        return
    guild = message.guild
    try:
        user = guild.get_member(payload.user_id)
    except AttributeError:
        return
    raid_dict = guild_dict[guild.id].setdefault('raidchannel_dict', {})
    config_dict = guild_dict[guild.id]['configure_dict']
    regions = _get_channel_regions(channel, 'raid')
    raid_channel = Meowth.get_channel(raid_report)
    gyms = None
    gyms = get_gyms(guild.id, regions)
    choices_list = ['Location', 'Hatch / Expire Time'] #'Boss / Tier',
    prompt = 'Which item would you like to modify?'
    match = await utils.ask_list(Meowth, prompt, channel, choices_list, user_list=user.id)
    if match in choices_list:
        if match == choices_list[0]:
            query_msg = await channel.send(embed=discord.Embed(colour=discord.Colour.gold(), description=_("What is the correct Location?")))
            try:
                gymmsg = await Meowth.wait_for('message', timeout=30, check=(lambda reply: reply.author == user))
            except asyncio.TimeoutError:
                await gymmsg.delete()
                gymmsg = None
            if not gymmsg:
                error = _("took too long to respond")
            elif gymmsg.clean_content.lower() == "cancel":
                error = _("cancelled the report")
                await gymmsg.delete()
            elif gymmsg:
                if gyms:
                    gym = await location_match_prompt(channel, user.id, gymmsg.clean_content, gyms)
                    if not gym:
                        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f"I couldn't find a gym named '{gymmsg.clean_content}'. Try again using the exact gym name!"))
                    location = gym.name
                    raid_channel_ids = get_existing_raid(guild, gym)
                    if raid_channel_ids:
                        raid_channel = Meowth.get_channel(raid_channel_ids[0])
                        if guild_dict[guild.id]['raidchannel_dict'][raid_channel.id]:
                            return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f"A raid has already been reported for {gym.name}"))
                    await update_raid_location(message, channel, raid_channel, gym)
                    await _refresh_listing_channels_internal(guild, "raid")
                    await channel.send(embed=discord.Embed(colour=discord.Colour.green(), description=_("Raid location updated")))
                    await gymmsg.delete()
                    await query_msg.delete()
        elif match == choices_list[1]:
            timewait = await channel.send(embed=discord.Embed(colour=discord.Colour.gold(), description=_("What is the Hatch / Expire time?")))
            try:
                timemsg = await Meowth.wait_for('message', timeout=30, check=(lambda reply: reply.author == user))
            except asyncio.TimeoutError:
                timemsg = None
                await timemsg.delete()
            if not timemsg:
                error = _("took too long to respond")
            elif timemsg.clean_content.lower() == "cancel":
                error = _("cancelled the report")
                await timemsg.delete()
            raidexp = await raid_time_check(raid_channel, timemsg.clean_content)
            if raidexp is not False:
                await _timerset(raid_channel, raidexp)
            await _refresh_listing_channels_internal(guild, "raid")
            await channel.send(embed=discord.Embed(colour=discord.Colour.green(), description=_("Raid hatch / expire time updated")))
            await timewait.delete()
            await timemsg.delete()
        await message.clear_reactions()
        await asyncio.sleep(0.25)
        await message.add_reaction('\u270f')
        await asyncio.sleep(0.25)
        await message.add_reaction('🚫')
        await asyncio.sleep(0.25)
    else:
        return

"""
Admin Commands
"""
@Meowth.command(hidden=True, name="eval")
@checks.is_dev_or_owner()
async def _eval(ctx, *, body: str):
    """Evaluates a code"""
    env = {
        'bot': ctx.bot,
        'ctx': ctx,
        'channel': ctx.channel,
        'author': ctx.author,
        'guild': ctx.guild,
        'message': ctx.message
    }
    def cleanup_code(content):
        """Automatically removes code blocks from the code."""
        # remove ```py\n```
        if content.startswith('```') and content.endswith('```'):
            return '\n'.join(content.split('\n')[1:-1])
        # remove `foo`
        return content.strip('` \n')
    env.update(globals())
    body = cleanup_code(body)
    stdout = io.StringIO()
    to_compile = (f'async def func():\n{textwrap.indent(body, "  ")}')
    try:
        exec(to_compile, env)
    except Exception as e:
        return await ctx.send(f'```py\n{e.__class__.__name__}: {e}\n```')
    func = env['func']
    try:
        with redirect_stdout(stdout):
            ret = await func()
    except Exception as e:
        value = stdout.getvalue()
        await ctx.send(f'```py\n{value}{traceback.format_exc()}\n```')
    else:
        value = stdout.getvalue()
        try:
            await ctx.message.add_reaction('\u2705')
        except:
            pass
        if ret is None:
            if value:
                paginator = commands.Paginator(prefix='```py')
                for line in textwrap.wrap(value, 80):
                    paginator.add_line(line.rstrip().replace('`', '\u200b`'))
                for p in paginator.pages:
                    await ctx.send(p)
        else:
            ctx.bot._last_result = ret
            await ctx.send(f'```py\n{value}{ret}\n```')

@Meowth.command()
@checks.is_owner()
async def save(ctx):
    """Save persistent state to file.

    Usage: !save
    File path is relative to current directory."""
    try:
        await _save()
        logger.info('CONFIG SAVED')
    except Exception as err:
        await _print(Meowth.owner, _('Error occured while trying to save!'))
        await _print(Meowth.owner, err)

async def _save():
    with tempfile.NamedTemporaryFile('wb', dir=os.path.dirname(os.path.join('data', 'serverdict')), delete=False) as tf:
        pickle.dump(guild_dict, tf, -1)
        tempname = tf.name
    try:
        os.remove(os.path.join('data', 'serverdict_backup'))
    except OSError as e:
        pass
    try:
        os.rename(os.path.join('data', 'serverdict'), os.path.join('data', 'serverdict_backup'))
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise
    os.rename(tempname, os.path.join('data', 'serverdict'))

@Meowth.command()
@checks.is_owner()
async def restart(ctx):
    """Restart after saving.

    Usage: !restart.
    Calls the save function and restarts Meowth."""
    try:
        await _save()
    except Exception as err:
        await _print(Meowth.owner, _('Error occured while trying to save!'))
        await _print(Meowth.owner, err)
    await ctx.channel.send(_('Restarting...'))
    Meowth._shutdown_mode = 26
    await Meowth.logout()

@Meowth.command()
@checks.is_owner()
async def exit(ctx):
    """Exit after saving.

    Usage: !exit.
    Calls the save function and quits the script."""
    try:
        await _save()
    except Exception as err:
        await _print(Meowth.owner, _('Error occured while trying to save!'))
        await _print(Meowth.owner, err)
    await ctx.channel.send(_('Shutting down...'))
    Meowth._shutdown_mode = 0
    await Meowth.logout()

@Meowth.command()
@commands.has_permissions(manage_guild=True)
async def kban(ctx, *, user: str = '', reason: str = ''):
    converter = commands.MemberConverter()
    try:
        trainer = await converter.convert(ctx, user)
        trainer_id = trainer.id
    except:
        return await ctx.channel.send("User not found.")   
    trainer = guild_dict[ctx.guild.id]['trainers'].setdefault(trainer_id,{})
    trainer['is_banned'] = True
    ban_reason = trainer.get('ban_reason')
    if not ban_reason:
        ban_reason = []
    elif not isinstance(ban_reason, list):
        ban_reason = [ban_reason]
    trainer['ban_reason'] = ban_reason.append(reason)
    try:
        await ctx.message.add_reaction('\u2705')
    except:
        pass

@Meowth.command()
@commands.has_permissions(manage_guild=True)
async def kunban(ctx, *, user: str = ''):
    channel = ctx.channel
    converter = commands.MemberConverter()
    try:
        trainer = await converter.convert(ctx, user)
        trainer_id = trainer.id
    except:
        return await channel.send("User not found.")   
    trainer = guild_dict[ctx.guild.id]['trainers'].get(trainer_id, None)
    trainer['is_banned'] = False
    try:
        await ctx.message.add_reaction('\u2705')
    except:
        pass

@Meowth.group(name='region', case_insensitive=True)
@checks.allowregion()
async def _region(ctx):
    """Handles user-region settings"""
    if ctx.invoked_subcommand == None:
        raise commands.BadArgument()

@_region.command(name="join")
async def join(ctx, *, region_names: str = ''):
    """Joins regional roles from the provided comma-separated list

    Examples:
    !region join kanto
    !region join kanto, johto, hoenn"""
    message = ctx.message
    guild = message.guild
    channel = message.channel
    author = message.author
    response = ""
    region_info_dict = guild_dict[guild.id]['configure_dict']['regions']['info']
    enabled_roles = set([r.get('role', None) for r in region_info_dict.values()])
    requested_roles = set([r for r in re.split(r'\s*,\s*', region_names.lower().replace(" ", "")) if r])
    if not requested_roles:
        return await channel.send(_user_region_list("join", author, enabled_roles))
    valid_requests = requested_roles & enabled_roles
    invalid_requests = requested_roles - enabled_roles
    role_objs = [discord.utils.get(guild.roles, name=role) for role in valid_requests]
    if role_objs:
        try:
            await author.add_roles(*role_objs, reason="user requested region role add via ")
            await message.add_reaction('✅')
            response += "Successfully joined "
        except:
            response += "Failed joining "
        response += f"{len(valid_requests)} roles:\n{', '.join(valid_requests)}"
    if invalid_requests:
        response += f"\n\n{len(invalid_requests)} invalid roles detected:\n{', '.join(invalid_requests)}\n\n"
        response += f"Acceptable regions are: {', '.join(enabled_roles)}"
    resp = await channel.send(response)
    await asyncio.sleep(20)
    await resp.delete()

@_region.command(name="leave")
async def _leave(ctx, *, region_names: str = ''):
    """Leaves regional roles from the provided comma-separated list

    Examples:
    !region leave kanto
    !region leave kanto, johto, hoenn"""
    message = ctx.message
    guild = message.guild
    channel = message.channel
    author = message.author
    response = ""
    region_info_dict = guild_dict[guild.id]['configure_dict']['regions']['info']
    enabled_roles = set([r.get('role', None) for r in region_info_dict.values()])
    requested_roles = set([r for r in re.split(r'\s*,\s*', region_names.lower().strip()) if r])
    if not requested_roles:
        return await channel.send(_user_region_list("leave", author, enabled_roles))
    valid_requests = requested_roles & enabled_roles
    invalid_requests = requested_roles - enabled_roles
    role_objs = [discord.utils.get(guild.roles, name=role) for role in valid_requests]
    if role_objs:
        try:
            await author.remove_roles(*role_objs, reason="user requested region role remove via ")
            await message.add_reaction('✅')
            response += "Successfully left "
        except:
            response += "Failed leaving "
        response += f"{len(valid_requests)} roles:\n{', '.join(valid_requests)}"
    if invalid_requests:
        response += f"\n\n{len(invalid_requests)} invalid roles detected:\n{', '.join(invalid_requests)}\n\n"
        response += f"Acceptable regions are: {', '.join(enabled_roles)}"
    resp = await channel.send(response)
    await asyncio.sleep(20)
    await resp.delete()
                  
def _user_region_list(action, author, enabled_roles):
    roles = [r.name for r in author.roles]
    response = f"Please select one or more regions separated by commas `!region {action} renton, kent`\n\n"
    if action == "join":
        response += f" Regions available to join are: {', '.join(set(enabled_roles).difference(roles)) or 'N/A'}"
    else:
        response += f" Regions available to leave are: {', '.join(set(enabled_roles).intersection(roles)) or 'N/A'}"
    return response

@_region.command(name="list")
async def _list(ctx):
    """Lists the user's active region roles

    Usage: !region list"""
    message = ctx.message
    guild = message.guild
    channel = message.channel
    author = message.author
    region_info_dict = guild_dict[guild.id]['configure_dict']['regions']['info']
    enabled_roles = set([r.get('role', None) for r in region_info_dict.values()])
    user_roles = set([r.name for r in author.roles])
    active_roles = user_roles & enabled_roles
    response = f"You have {len(active_roles)} active region roles:\n{', '.join(active_roles)}"
    response += f" Regions available to join are: {', '.join(set(active_roles).difference(enabled_roles)) or 'N/A'}"
    await message.add_reaction('✅')
    resp = await channel.send(response)
    await asyncio.sleep(20)
    await resp.delete()

@Meowth.group(name='set', case_insensitive=True)
async def _set(ctx):
    """Changes a setting."""
    if ctx.invoked_subcommand == None:
        raise commands.BadArgument()

@_set.command()
@commands.has_permissions(manage_guild=True)
async def regional(ctx, regional):
    """Changes server regional pokemon."""
    regional = regional.lower()
    if regional == "reset" and checks.is_dev_or_owner(ctx):
        msg = _("Are you sure you want to clear all regionals?")
        question = await ctx.channel.send(msg)
        try:
            timeout = False
            res, reactuser = await ask(question, ctx.message.channel, ctx.message.author.id)
        except TypeError:
            timeout = True
        await question.delete()
        if timeout or res.emoji == '❎':
            return
        elif res.emoji == '✅':
            pass
        else:
            return
        guild_dict_copy = copy.deepcopy(guild_dict)
        for guildid in guild_dict_copy.keys():
            guild_dict[guildid]['configure_dict']['settings']['regional'] = None
        return
    elif regional == 'clear':
        regional = None
        _set_regional(Meowth, ctx.guild, regional)
        await ctx.message.channel.send(_("Regional raid boss cleared!"))
        return
    regional = Pokemon.get_pokemon(Meowth, regional)
    if regional.is_raid:
        _set_regional(Meowth, ctx.guild, regional)
        await ctx.message.channel.send(_("Regional raid boss set to **{boss}**!").format(boss=regional.name))
    else:
        await ctx.message.channel.send(_("That Pokemon doesn't appear in raids!"))
        return

def _set_regional(bot, guild, regional):
    bot.guild_dict[guild.id]['configure_dict']['settings']['regional'] = regional

@_set.command()
@commands.has_permissions(manage_guild=True)
async def timezone(ctx,*, timezone: str = ''):
    """Changes server timezone."""
    try:
        timezone = float(timezone)
    except ValueError:
        await ctx.channel.send(_("I couldn't convert your answer to an appropriate timezone! Please double check what you sent me and resend a number from **-12** to **12**."))
        return
    if (not ((- 12) <= timezone <= 14)):
        await ctx.channel.send(_("I couldn't convert your answer to an appropriate timezone! Please double check what you sent me and resend a number from **-12** to **12**."))
        return
    _set_timezone(Meowth, ctx.guild, timezone)
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[ctx.channel.guild.id]['configure_dict']['settings']['offset'])
    await ctx.channel.send(_("Timezone has been set to: `UTC{offset}`\nThe current time is **{now}**").format(offset=timezone,now=now.strftime("%H:%M")))

def _set_timezone(bot, guild, timezone):
    bot.guild_dict[guild.id]['configure_dict']['settings']['offset'] = timezone

@_set.command()
@commands.has_permissions(manage_guild=True)
async def prefix(ctx, prefix=None):
    """Changes server prefix."""
    if prefix == 'clear':
        prefix = None
    prefix = prefix.strip()
    _set_prefix(Meowth, ctx.guild, prefix)
    if prefix != None:
        await ctx.channel.send(_('Prefix has been set to: `{}`').format(prefix))
    else:
        default_prefix = Meowth.config['default_prefix']
        await ctx.channel.send(_('Prefix has been reset to default: `{}`').format(default_prefix))

def _set_prefix(bot, guild, prefix):
    bot.guild_dict[guild.id]['configure_dict']['settings']['prefix'] = prefix

@_set.command()
async def silph(ctx, silph_user: str = None):
    """Links a server member to a Silph Road Travelers Card."""
    if not silph_user:
        await ctx.send(_('Silph Road Travelers Card cleared!'))
        try:
            del guild_dict[ctx.guild.id]['trainers'][ctx.author.id]['silphid']
        except:
            pass
        return

    silph_cog = ctx.bot.cogs.get('Silph')
    if not silph_cog:
        return await ctx.send(
            _("The Silph Extension isn't accessible at the moment, sorry!"))

    async with ctx.typing():
        card = await silph_cog.get_silph_card(silph_user)
        if not card:
            return await ctx.send(_('Silph Card for {silph_user} not found.').format(silph_user=silph_user))

    if not card.discord_name:
        return await ctx.send(
            _('No Discord account found linked to this Travelers Card!'))

    if card.discord_name != str(ctx.author):
        return await ctx.send(
            _('This Travelers Card is linked to another Discord account!'))

    try:
        offset = ctx.bot.guild_dict[ctx.guild.id]['configure_dict']['settings']['offset']
    except KeyError:
        offset = None

    trainers = guild_dict[ctx.guild.id].get('trainers', {})
    author = trainers.get(ctx.author.id,{})
    author['silphid'] = silph_user
    trainers[ctx.author.id] = author
    guild_dict[ctx.guild.id]['trainers'] = trainers

    await ctx.send(
        _('This Travelers Card has been successfully linked to you!'),
        embed=card.embed(offset))

@_set.command()
async def pokebattler(ctx, pbid: int = 0):
    """Links a server member to a PokeBattler ID."""
    if not pbid:
        await ctx.send(_('Pokebattler ID cleared!'))
        try:
            del guild_dict[ctx.guild.id]['trainers'][ctx.author.id]['pokebattlerid']
        except:
            pass
        return
    trainers = guild_dict[ctx.guild.id].get('trainers',{})
    author = trainers.get(ctx.author.id,{})
    author['pokebattlerid'] = pbid
    trainers[ctx.author.id] = author
    guild_dict[ctx.guild.id]['trainers'] = trainers
    await ctx.send(_('Pokebattler ID set to {pbid}!').format(pbid=pbid))

@Meowth.group(name='get', case_insensitive=True)
@commands.has_permissions(manage_guild=True)
async def _get(ctx):
    """Get a setting value"""
    if ctx.invoked_subcommand == None:
        raise commands.BadArgument()

@_get.command()
@commands.has_permissions(manage_guild=True)
async def prefix(ctx):
    """Get server prefix."""
    prefix = _get_prefix(Meowth, ctx.message)
    await ctx.channel.send(_('Prefix for this server is: `{}`').format(prefix))

@_get.command()
@commands.has_permissions(manage_guild=True)
async def perms(ctx, channel_id = None):
    """Show Kyogre's permissions for the guild and channel."""
    channel = discord.utils.get(ctx.bot.get_all_channels(), id=channel_id)
    guild = channel.guild if channel else ctx.guild
    channel = channel or ctx.channel
    guild_perms = guild.me.guild_permissions
    chan_perms = channel.permissions_for(guild.me)
    req_perms = discord.Permissions(268822608)

    embed = discord.Embed(colour=ctx.guild.me.colour)
    embed.set_author(name=_('Bot Permissions'), icon_url="https://i.imgur.com/wzryVaS.png")

    wrap = functools.partial(textwrap.wrap, width=20)
    names = [wrap(channel.name), wrap(guild.name)]
    if channel.category:
        names.append(wrap(channel.category.name))
    name_len = max(len(n) for n in names)
    def same_len(txt):
        return '\n'.join(txt + ([' '] * (name_len-len(txt))))
    names = [same_len(n) for n in names]
    chan_msg = [f"**{names[0]}** \n{channel.id} \n"]
    guild_msg = [f"**{names[1]}** \n{guild.id} \n"]
    def perms_result(perms):
        data = []
        meet_req = perms >= req_perms
        result = _("**PASS**") if meet_req else _("**FAIL**")
        data.append(f"{result} - {perms.value} \n")
        true_perms = [k for k, v in dict(perms).items() if v is True]
        false_perms = [k for k, v in dict(perms).items() if v is False]
        req_perms_list = [k for k, v in dict(req_perms).items() if v is True]
        true_perms_str = '\n'.join(true_perms)
        if not meet_req:
            missing = '\n'.join([p for p in false_perms if p in req_perms_list])
            meet_req_result = _("**MISSING**")
            data.append(f"{meet_req_result} \n{missing} \n")
        if true_perms_str:
            meet_req_result = _("**ENABLED**")
            data.append(f"{meet_req_result} \n{true_perms_str} \n")
        return '\n'.join(data)
    guild_msg.append(perms_result(guild_perms))
    chan_msg.append(perms_result(chan_perms))
    embed.add_field(name=_('GUILD'), value='\n'.join(guild_msg))
    if channel.category:
        cat_perms = channel.category.permissions_for(guild.me)
        cat_msg = [f"**{names[2]}** \n{channel.category.id} \n"]
        cat_msg.append(perms_result(cat_perms))
        embed.add_field(name=_('CATEGORY'), value='\n'.join(cat_msg))
    embed.add_field(name=_('CHANNEL'), value='\n'.join(chan_msg))

    try:
        await ctx.send(embed=embed)
    except discord.errors.Forbidden:
        # didn't have permissions to send a message with an embed
        try:
            msg = _("I couldn't send an embed here, so I've sent you a DM")
            await ctx.send(msg)
        except discord.errors.Forbidden:
            # didn't have permissions to send a message at all
            pass
        await ctx.author.send(embed=embed)

@Meowth.command()
@commands.has_permissions(manage_guild=True)
async def welcome(ctx, user: discord.Member=None):
    """Test welcome on yourself or mentioned member.

    Usage: !welcome [@member]"""
    if (not user):
        user = ctx.author
    await on_member_join(user)

@Meowth.command(hidden=True)
@commands.has_permissions(manage_guild=True)
async def outputlog(ctx):
    """Get current Kyogre log.

    Usage: !outputlog
    Output is a link to hastebin."""
    with open(os.path.join('logs', 'kyogre.log'), 'r', encoding='latin-1', errors='replace') as logfile:
        logdata = logfile.read()
    await ctx.channel.send(hastebin.post(logdata))

@Meowth.command(aliases=['say'])
@commands.has_permissions(manage_guild=True)
async def announce(ctx, *, announce=None):
    """Repeats your message in an embed from Kyogre.

    Usage: !announce [announcement]
    If the announcement isn't added at the same time as the command, Kyogre will wait 3 minutes for a followup message containing the announcement."""
    message = ctx.message
    channel = message.channel
    guild = message.guild
    author = message.author
    if announce == None:
        announcewait = await channel.send(_("I'll wait for your announcement!"))
        announcemsg = await Meowth.wait_for('message', timeout=180, check=(lambda reply: reply.author == message.author))
        await announcewait.delete()
        if announcemsg != None:
            announce = announcemsg.content
            await announcemsg.delete()
        else:
            confirmation = await channel.send(_("You took too long to send me your announcement! Retry when you're ready."))
    embeddraft = discord.Embed(colour=guild.me.colour, description=announce)
    if ctx.invoked_with == "announce":
        title = _('Announcement')
        if Meowth.user.avatar_url:
            embeddraft.set_author(name=title, icon_url=Meowth.user.avatar_url)
        else:
            embeddraft.set_author(name=title)
    draft = await channel.send(embed=embeddraft)
    reaction_list = ['❔', '✅', '❎']
    owner_msg_add = ''
    if checks.is_owner_check(ctx):
        owner_msg_add = '🌎 '
        owner_msg_add += _('to send it to all servers, ')
        reaction_list.insert(0, '🌎')

    def check(reaction, user):
        if user.id == author.id:
            if (str(reaction.emoji) in reaction_list) and (reaction.message.id == rusure.id):
                return True
        return False
    msg = _("That's what you sent, does it look good? React with ")
    msg += "{}❔ "
    msg += _("to send to another channel, ")
    msg += "✅ "
    msg += _("to send it to this channel, or ")
    msg += "❎ "
    msg += _("to cancel")
    rusure = await channel.send(msg.format(owner_msg_add))
    try:
        timeout = False
        res, reactuser = await ask(rusure, channel, author.id, react_list=reaction_list)
    except TypeError:
        timeout = True
    if not timeout:
        await rusure.delete()
        if res.emoji == '❎':
            confirmation = await channel.send(_('Announcement Cancelled.'))
            await draft.delete()
        elif res.emoji == '✅':
            confirmation = await channel.send(_('Announcement Sent.'))
        elif res.emoji == '❔':
            channelwait = await channel.send(_('What channel would you like me to send it to?'))
            channelmsg = await Meowth.wait_for('message', timeout=60, check=(lambda reply: reply.author == message.author))
            if channelmsg.content.isdigit():
                sendchannel = Meowth.get_channel(int(channelmsg.content))
            elif channelmsg.raw_channel_mentions:
                sendchannel = Meowth.get_channel(channelmsg.raw_channel_mentions[0])
            else:
                sendchannel = discord.utils.get(guild.text_channels, name=channelmsg.content)
            if (channelmsg != None) and (sendchannel != None):
                announcement = await sendchannel.send(embed=embeddraft)
                confirmation = await channel.send(_('Announcement Sent.'))
            elif sendchannel == None:
                confirmation = await channel.send(_("That channel doesn't exist! Retry when you're ready."))
            else:
                confirmation = await channel.send(_("You took too long to send me your announcement! Retry when you're ready."))
            await channelwait.delete()
            await channelmsg.delete()
            await draft.delete()
        elif (res.emoji == '🌎') and checks.is_owner_check(ctx):
            failed = 0
            sent = 0
            count = 0
            recipients = {

            }
            embeddraft.set_footer(text=_('For support, contact us on our Discord server. Invite Code: hhVjAN8'))
            embeddraft.colour = discord.Colour.lighter_grey()
            for guild in Meowth.guilds:
                recipients[guild.name] = guild.owner
            for (guild, destination) in recipients.items():
                try:
                    await destination.send(embed=embeddraft)
                except discord.HTTPException:
                    failed += 1
                    logger.info('Announcement Delivery Failure: {} - {}'.format(destination.name, guild))
                else:
                    sent += 1
                count += 1
            logger.info('Announcement sent to {} server owners: {} successful, {} failed.'.format(count, sent, failed))
            confirmation = await channel.send(_('Announcement sent to {} server owners: {} successful, {} failed.').format(count, sent, failed))
        await asyncio.sleep(10)
        await confirmation.delete()
    else:
        await rusure.delete()
        confirmation = await channel.send(_('Announcement Timed Out.'))
        await asyncio.sleep(10)
        await confirmation.delete()
    await asyncio.sleep(30)
    await message.delete()

@Meowth.group(case_insensitive=True, invoke_without_command=True)
@commands.has_permissions(manage_guild=True)
async def configure(ctx, *, configlist: str=""):
    """Kyogre Configuration

    Usage: !configure [list]
    Kyogre will DM you instructions on how to configure Kyogre for your server.
    If it is not your first time configuring, you can choose a section to jump to.
    You can also include a comma separated [list] of sections from the following:
    all, team, welcome, regions, raid, exraid, invite, counters, wild, research, meetup, subscription, archive, trade, timezone"""
    await _configure(ctx, configlist)

async def _configure(ctx, configlist):
    guild = ctx.message.guild
    owner = ctx.message.author
    try:
        await ctx.message.delete()
    except (discord.errors.Forbidden, discord.errors.HTTPException):
        pass
    config_sessions = guild_dict[ctx.guild.id]['configure_dict']['settings'].setdefault('config_sessions',{}).setdefault(owner.id,0) + 1
    guild_dict[ctx.guild.id]['configure_dict']['settings']['config_sessions'][owner.id] = config_sessions
    for session in guild_dict[guild.id]['configure_dict']['settings']['config_sessions'].keys():
        if not guild.get_member(session):
            del guild_dict[guild.id]['configure_dict']['settings']['config_sessions'][session]
    config_dict_temp = getattr(ctx, 'config_dict_temp',copy.deepcopy(guild_dict[guild.id]['configure_dict']))
    firstconfig = False
    all_commands = ['team', 'welcome', 'regions', 'raid', 'exraid', 'invite', 'counters', 'wild', 'research', 'meetup', 'subscription', 'archive', 'trade', 'timezone']
    enabled_commands = []
    configreplylist = []
    config_error = False
    if not config_dict_temp['settings']['done']:
        firstconfig = True
    if configlist and not firstconfig:
        configlist = configlist.lower().replace("timezone","settings").split(",")
        configlist = [x.strip().lower() for x in configlist]
        diff = set(configlist) - set(all_commands)
        if diff and "all" in diff:
            configreplylist = all_commands
        elif not diff:
            configreplylist = configlist
        else:
            await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("I'm sorry, I couldn't understand some of what you entered. Let's just start here.")))
    if config_dict_temp['settings']['config_sessions'][owner.id] > 1:
        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("**MULTIPLE SESSIONS!**\n\nIt looks like you have **{yoursessions}** active configure sessions. I recommend you send **cancel** first and then send your request again to avoid confusing me.\n\nYour Sessions: **{yoursessions}** | Total Sessions: **{allsessions}**").format(allsessions=sum(config_dict_temp['settings']['config_sessions'].values()),yoursessions=config_dict_temp['settings']['config_sessions'][owner.id])))
    configmessage = _("Welcome to the configuration for Kyogre! I will be guiding you through some steps to get me setup on your server.\n\n**Role Setup**\nBefore you begin the configuration, please make sure my role is moved to the top end of the server role hierarchy. It can be under admins and mods, but must be above team and general roles. [Here is an example](http://i.imgur.com/c5eaX1u.png)")
    if not firstconfig and not configreplylist:
        configmessage += _("\n\n**Welcome Back**\nThis isn't your first time configuring. You can either reconfigure everything by replying with **all** or reply with a comma separated list to configure those commands. Example: `subscription, raid, wild`")
        for commandconfig in config_dict_temp.keys():
            if config_dict_temp[commandconfig].get('enabled',False):
                enabled_commands.append(commandconfig)
        configmessage += _("\n\n**Enabled Commands:**\n{enabled_commands}").format(enabled_commands=", ".join(enabled_commands))
        configmessage += _("\n\n**All Commands:**\n**all** - To redo configuration\n**team** - For Team Assignment configuration\n**welcome** - For Welcome Message configuration\n**regions** - for region configuration\n**raid** - for raid command configuration\n**exraid** - for EX raid command configuration\n**invite** - for invite command configuration\n**counters** - for automatic counters configuration\n**wild** - for wild command configuration\n**research** - for !research command configuration\n**meetup** - for !meetup command configuration\n**subscription** - for subscription command configuration\n**archive** - For !archive configuration\n**trade** - For trade command configuration\n**timezone** - For timezone configuration")
        configmessage += _('\n\nReply with **cancel** at any time throughout the questions to cancel the configure process.')
        await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=configmessage).set_author(name=_('Kyogre Configuration - {guild}').format(guild=guild.name), icon_url=Meowth.user.avatar_url))
        while True:
            config_error = False
            def check(m):
                return m.guild == None and m.author == owner
            configreply = await Meowth.wait_for('message', check=check)
            configreply.content = configreply.content.replace("timezone", "settings")
            if configreply.content.lower() == 'cancel':
                await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                del guild_dict[guild.id]['configure_dict']['settings']['config_sessions'][owner.id]
                return None
            elif "all" in configreply.content.lower():
                configreplylist = all_commands
                break
            else:
                configreplylist = configreply.content.lower().split(",")
                configreplylist = [x.strip() for x in configreplylist]
                for configreplyitem in configreplylist:
                    if configreplyitem not in all_commands:
                        config_error = True
                        break
            if config_error:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("I'm sorry I don't understand. Please reply with the choices above.")))
                continue
            else:
                break
    elif firstconfig == True:
        configmessage += _('\n\nReply with **cancel** at any time throughout the questions to cancel the configure process.')
        await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=configmessage).set_author(name=_('Kyogre Configuration - {guild}').format(guild=guild.name), icon_url=Meowth.user.avatar_url))
        configreplylist = all_commands
    try:
        if "team" in configreplylist:
            ctx = await _configure_team(ctx)
            if not ctx:
                return None
        if "welcome" in configreplylist:
            ctx = await _configure_welcome(ctx)
            if not ctx:
                return None
        if "regions" in configreplylist:
            ctx = await _configure_regions(ctx)
            if not ctx:
                return None
        if "raid" in configreplylist:
            ctx = await _configure_raid(ctx)
            if not ctx:
                return None
        if "exraid" in configreplylist:
            ctx = await _configure_exraid(ctx)
            if not ctx:
                return None
        if "meetup" in configreplylist:
            ctx = await _configure_meetup(ctx)
            if not ctx:
                return None
        if "invite" in configreplylist:
            ctx = await _configure_invite(ctx)
            if not ctx:
                return None
        if "counters" in configreplylist:
            ctx = await _configure_counters(ctx)
            if not ctx:
                return None
        if "wild" in configreplylist:
            ctx = await _configure_wild(ctx)
            if not ctx:
                return None
        if "research" in configreplylist:
            ctx = await _configure_research(ctx)
            if not ctx:
                return None
        if "subscription" in configreplylist:
            ctx = await _configure_subscription(ctx)
            if not ctx:
                return None
        if "archive" in configreplylist:
            ctx = await _configure_archive(ctx)
            if not ctx:
                return None
        if "trade" in configreplylist:
            ctx = await _configure_trade(ctx)
            if not ctx:
                return None
        if "settings" in configreplylist:
            ctx = await _configure_settings(ctx)
            if not ctx:
                return None
    finally:
        if ctx:
            ctx.config_dict_temp['settings']['done'] = True
            guild_dict[guild.id]['configure_dict'] = ctx.config_dict_temp
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("Alright! Your settings have been saved and I'm ready to go! If you need to change any of these settings, just type **!configure** in your server again.")).set_author(name=_('Configuration Complete'), icon_url=Meowth.user.avatar_url))
        del guild_dict[guild.id]['configure_dict']['settings']['config_sessions'][owner.id]

@configure.command(name='all')
async def configure_all(ctx):
    """All settings"""
    await _configure(ctx, "all")

async def _check_sessions_and_invoke(ctx, func_ref):
    guild = ctx.message.guild
    owner = ctx.message.author
    try:
        await ctx.message.delete()
    except (discord.errors.Forbidden, discord.errors.HTTPException):
        pass
    if not guild_dict[guild.id]['configure_dict']['settings']['done']:
        await _configure(ctx, "all")
        return
    config_sessions = guild_dict[ctx.guild.id]['configure_dict']['settings'].setdefault('config_sessions',{}).setdefault(owner.id,0) + 1
    guild_dict[ctx.guild.id]['configure_dict']['settings']['config_sessions'][owner.id] = config_sessions
    if guild_dict[guild.id]['configure_dict']['settings']['config_sessions'][owner.id] > 1:
        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("**MULTIPLE SESSIONS!**\n\nIt looks like you have **{yoursessions}** active configure sessions. I recommend you send **cancel** first and then send your request again to avoid confusing me.\n\nYour Sessions: **{yoursessions}** | Total Sessions: **{allsessions}**").format(allsessions=sum(guild_dict[guild.id]['configure_dict']['settings']['config_sessions'].values()),yoursessions=guild_dict[guild.id]['configure_dict']['settings']['config_sessions'][owner.id])))
    ctx = await func_ref(ctx)
    if ctx:
        guild_dict[guild.id]['configure_dict'] = ctx.config_dict_temp
        await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("Alright! Your settings have been saved and I'm ready to go! If you need to change any of these settings, just type **!configure** in your server again.")).set_author(name=_('Configuration Complete'), icon_url=Meowth.user.avatar_url))
    del guild_dict[guild.id]['configure_dict']['settings']['config_sessions'][owner.id]

@configure.command()
async def team(ctx):
    """!team command settings"""
    return await _check_sessions_and_invoke(ctx, _configure_team)

async def _configure_team(ctx):
    guild = ctx.message.guild
    owner = ctx.message.author
    config_dict_temp = getattr(ctx, 'config_dict_temp',copy.deepcopy(guild_dict[guild.id]['configure_dict']))
    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("Team assignment allows users to assign their Pokemon Go team role using the **!team** command. If you have a bot that handles this already, you may want to disable this feature.\n\nIf you are to use this feature, ensure existing team roles are as follows: mystic, valor, instinct. These must be all lowercase letters. If they don't exist yet, I'll make some for you instead.\n\nRespond here with: **N** to disable, **Y** to enable:")).set_author(name=_('Team Assignments'), icon_url=Meowth.user.avatar_url))
    while True:
        teamreply = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
        if teamreply.content.lower() == 'y':
            config_dict_temp['team']['enabled'] = True
            guild_roles = []
            for role in guild.roles:
                if role.name.lower() in config['team_dict'] and role.name not in guild_roles:
                    guild_roles.append(role.name)
            lowercase_roles = [element.lower() for element in guild_roles]
            for team in config['team_dict'].keys():
                temp_role = discord.utils.get(guild.roles, name=team)
                if temp_role == None:
                    try:
                        await guild.create_role(name=team, hoist=False, mentionable=True)
                    except discord.errors.HTTPException:
                        pass
            await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Team Assignments enabled!')))
            break
        elif teamreply.content.lower() == 'n':
            config_dict_temp['team']['enabled'] = False
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Team Assignments disabled!')))
            break
        elif teamreply.content.lower() == 'cancel':
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
            return None
        else:
            await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("I'm sorry I don't understand. Please reply with either **N** to disable, or **Y** to enable.")))
            continue
    ctx.config_dict_temp = config_dict_temp
    return ctx

@configure.command()
async def welcome(ctx):
    """Welcome message settings"""
    return await _check_sessions_and_invoke(ctx, _configure_welcome)

async def _configure_welcome(ctx):
    guild = ctx.message.guild
    owner = ctx.message.author
    config_dict_temp = getattr(ctx, 'config_dict_temp',copy.deepcopy(guild_dict[guild.id]['configure_dict']))
    welcomeconfig = _('I can welcome new members to the server with a short message. Here is an example, but it is customizable:\n\n')
    if config_dict_temp['team']['enabled']:
        welcomeconfig += _("Welcome to {server_name}, {owner_name.mention}! Set your team by typing '**!team mystic**' or '**!team valor**' or '**!team instinct**' without quotations. If you have any questions just ask an admin.").format(server_name=guild.name, owner_name=owner)
    else:
        welcomeconfig += _('Welcome to {server_name}, {owner_name.mention}! If you have any questions just ask an admin.').format(server_name=guild, owner_name=owner)
    welcomeconfig += _('\n\nThis welcome message can be in a specific channel or a direct message. If you have a bot that handles this already, you may want to disable this feature.\n\nRespond with: **N** to disable, **Y** to enable:')
    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=welcomeconfig).set_author(name=_('Welcome Message'), icon_url=Meowth.user.avatar_url))
    while True:
        welcomereply = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
        if welcomereply.content.lower() == 'y':
            config_dict_temp['welcome']['enabled'] = True
            await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Welcome Message enabled!')))
            await owner.send(embed=discord.Embed(
                colour=discord.Colour.lighter_grey(),
                description=(_("Would you like a custom welcome message? "
                             "You can reply with **N** to use the default message above or enter your own below.\n\n"
                             "I can read all [discord formatting](https://support.discordapp.com/hc/en-us/articles/210298617-Markdown-Text-101-Chat-Formatting-Bold-Italic-Underline-) "
                             "and I have the following template tags:\n\n"
                             "**{@member}** - Replace member with user name or ID\n"
                             "**{#channel}** - Replace channel with channel name or ID\n"
                             "**{&role}** - Replace role name or ID (shows as @deleted-role DM preview)\n"
                             "**{user}** - Will mention the new user\n"
                             "**{server}** - Will print your server's name\n"
                             "Surround your message with [] to send it as an embed. **Warning:** Mentions within embeds may be broken on mobile, this is a Discord bug."))).set_author(name=_("Welcome Message"), icon_url=Meowth.user.avatar_url))
            if config_dict_temp['welcome']['welcomemsg'] != 'default':
                await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=config_dict_temp['welcome']['welcomemsg']).set_author(name=_("Current Welcome Message"), icon_url=Meowth.user.avatar_url))
            while True:
                welcomemsgreply = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and (message.author == owner)))
                if welcomemsgreply.content.lower() == 'n':
                    config_dict_temp['welcome']['welcomemsg'] = 'default'
                    await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_("Default welcome message set")))
                    break
                elif welcomemsgreply.content.lower() == "cancel":
                    await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_("**CONFIG CANCELLED!**\n\nNo changes have been made.")))
                    return None
                elif len(welcomemsgreply.content) > 500:
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("Please shorten your message to less than 500 characters. You entered {count}.").format(count=len(welcomemsgreply.content))))
                    continue
                else:
                    welcomemessage, errors = do_template(welcomemsgreply.content, owner, guild)
                    if errors:
                        if welcomemessage.startswith("[") and welcomemessage.endswith("]"):
                            embed = discord.Embed(colour=guild.me.colour, description=welcomemessage[1:-1].format(user=owner.mention))
                            embed.add_field(name=_('Warning'), value=_('The following could not be found:\n{}').format('\n'.join(errors)))
                            await owner.send(embed=embed)
                        else:
                            await owner.send(_("{msg}\n\n**Warning:**\nThe following could not be found: {errors}").format(msg=welcomemessage, errors=', '.join(errors)))
                        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("Please check the data given and retry a new welcome message, or reply with **N** to use the default.")))
                        continue
                    else:
                        if welcomemessage.startswith("[") and welcomemessage.endswith("]"):
                            embed = discord.Embed(colour=guild.me.colour, description=welcomemessage[1:-1].format(user=owner.mention))
                            question = await owner.send(content=_("Here's what you sent. Does it look ok?"),embed=embed)
                            try:
                                timeout = False
                                res, reactuser = await ask(question, owner, owner.id)
                            except TypeError:
                                timeout = True
                        else:
                            question = await owner.send(content=_("Here's what you sent. Does it look ok?\n\n{welcome}").format(welcome=welcomemessage.format(user=owner.mention)))
                            try:
                                timeout = False
                                res, reactuser = await ask(question, owner, owner.id)
                            except TypeError:
                                timeout = True
                    if timeout or res.emoji == '❎':
                        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("Please enter a new welcome message, or reply with **N** to use the default.")))
                        continue
                    else:
                        config_dict_temp['welcome']['welcomemsg'] = welcomemessage
                        await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_("Welcome Message set to:\n\n{}").format(config_dict_temp['welcome']['welcomemsg'])))
                        break
                break
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("Which channel in your server would you like me to post the Welcome Messages? You can also choose to have them sent to the new member via Direct Message (DM) instead.\n\nRespond with: **channel-name** or ID of a channel in your server or **DM** to Direct Message:")).set_author(name=_("Welcome Message Channel"), icon_url=Meowth.user.avatar_url))
            while True:
                welcomechannelreply = await Meowth.wait_for('message',check=lambda message: message.guild == None and message.author == owner)
                if welcomechannelreply.content.lower() == "dm":
                    config_dict_temp['welcome']['welcomechan'] = "dm"
                    await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_("Welcome DM set")))
                    break
                elif " " in welcomechannelreply.content.lower():
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("Channel names can't contain spaces, sorry. Please double check the name and send your response again.")))
                    continue
                elif welcomechannelreply.content.lower() == "cancel":
                    await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                    return None
                else:
                    item = welcomechannelreply.content
                    channel = None
                    if item.isdigit():
                        channel = discord.utils.get(guild.text_channels, id=int(item))
                    if not channel:
                        item = re.sub('[^a-zA-Z0-9 _\\-]+', '', item)
                        item = item.replace(" ","-")
                        name = await letter_case(guild.text_channels, item.lower())
                        channel = discord.utils.get(guild.text_channels, name=name)
                    if channel:
                        guild_channel_list = []
                        for textchannel in guild.text_channels:
                            guild_channel_list.append(textchannel.id)
                        diff = set([channel.id]) - set(guild_channel_list)
                    else:
                        diff = True
                    if (not diff):
                        config_dict_temp['welcome']['welcomechan'] = channel.id
                        ow = channel.overwrites_for(Meowth.user)
                        ow.send_messages = True
                        ow.read_messages = True
                        ow.manage_roles = True
                        try:
                            await channel.set_permissions(Meowth.user, overwrite = ow)
                        except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
                            await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_('I couldn\'t set my own permissions in this channel. Please ensure I have the correct permissions in {channel} using **{prefix}get perms**.').format(prefix=ctx.prefix, channel=channel.mention)))
                        await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Welcome Channel set to {channel}').format(channel=welcomechannelreply.content.lower())))
                        break
                    else:
                        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The channel you provided isn't in your server. Please double check your channel and resend your response.")))
                        continue
                break
            break
        elif welcomereply.content.lower() == 'n':
            config_dict_temp['welcome']['enabled'] = False
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Welcome Message disabled!')))
            break
        elif welcomereply.content.lower() == 'cancel':
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
            return None
        else:
            await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("I'm sorry I don't understand. Please reply with either **N** to disable, or **Y** to enable.")))
            continue
    ctx.config_dict_temp = config_dict_temp
    return ctx

@configure.command()
async def regions(ctx):
    """region configuration for server"""
    return await _check_sessions_and_invoke(ctx, _configure_regions)

async def _configure_regions(ctx):
    guild = ctx.message.guild
    owner = ctx.message.author
    config_dict_temp = getattr(ctx, 'config_dict_temp',copy.deepcopy(guild_dict[guild.id]['configure_dict']))
    config_dict_temp.setdefault('regions', {})
    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("I can keep track of multiple regions within your community. This can be useful for communities that span multiple cities or areas where users tend to only be interested in certain subsets of raids, research, etc. To start, I'll need the names of the regions you'd like to set up: `region-name, region-name, region-name`\n\nExample: `north-saffron, south-saffron, celadon`\n\nTo facilitate communication, I will be creating roles for each region name provided, so make sure the names are meaningful!\n\nIf you do not require regions, you may want to disable this functionality.\n\nRespond with: **N** to disable, or the **region-name** list to enable, each seperated with a comma and space:")).set_author(name=_('Region Names'), icon_url=Meowth.user.avatar_url))
    region_dict = {}
    while True:
        region_names = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
        response = region_names.content.strip().lower()
        if response == 'n':
            config_dict_temp['regions']['enabled'] = False
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Regions disabled')))
            break
        elif response == 'cancel':
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
            return None
        else:
            config_dict_temp['regions']['enabled'] = True
            region_names_list = re.split(r'\s*,\s*', response)
        break
    if config_dict_temp['regions']['enabled']:
        await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('Occasionally I will generate Google Maps links to give people directions to locations! To do this, I need to know what city/town/area each region represents to ensure I get the right location in the map. For each region name you provided, I will need its corresponding general location using only letters and spaces, with each location seperated by a comma and space.\n\nExample: `saffron city kanto, saffron city kanto, celadon city kanto`\n\nEach location will have to be in the same order as you provided the names in the previous question.\n\nRespond with: **location info, location info, location info** each matching the order of the previous region name list below.')).set_author(name=_('Region Locations'), icon_url=Meowth.user.avatar_url))
        await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{region_name_list}').format(region_name_list=response[:2000])).set_author(name=_('Entered Regions'), icon_url=Meowth.user.avatar_url))
        while True:
            locations = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
            response = locations.content.strip().lower()
            if response == 'cancel':
                await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                return None
            region_locations_list = re.split(r'\s*,\s*', response)
            if len(region_locations_list) == len(region_names_list):
                for i in range(len(region_names_list)):
                    region_dict[region_names_list[i]] = {'location': region_locations_list[i], 'role': sanitize_name(region_names_list[i])}
                break
            else:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The number of locations doesn't match the number of regions you gave me earlier!\n\nI'll show you the two lists to compare:\n\n{region_names_list}\n{region_locations_list}\n\nPlease double check that your locations match up with your provided region names and resend your response.").format(region_names_list=', '.join(region_names_list), region_locations_list=', '.join(region_locations_list))))
                continue
        await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Region locations are set')))
        await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('Lastly, I need to know what channels should be flagged to allow users to modify their region assignments. Please enter the channels to be used for this as a comma-separated list. \n\nExample: `general, region-assignment`\n\nNote that this answer does *not* directly correspond to the previously entered channels/regions.\n\n')).set_author(name=_('Region Command Channels'), icon_url=Meowth.user.avatar_url))
        while True:
            locations = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
            response = locations.content.strip().lower()
            if response == 'cancel':
                await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                return None
            channel_list = [c.strip() for c in response.split(',')]
            guild_channel_list = []
            for channel in guild.text_channels:
                guild_channel_list.append(channel.id)
            channel_objs = []
            channel_names = []
            channel_errors = []
            for item in channel_list:
                channel = None
                if item.isdigit():
                    channel = discord.utils.get(guild.text_channels, id=int(item))
                if not channel:
                    item = re.sub('[^a-zA-Z0-9 _\\-]+', '', item)
                    item = item.replace(" ","-")
                    name = await letter_case(guild.text_channels, item.lower())
                    channel = discord.utils.get(guild.text_channels, name=name)
                if channel:
                    channel_objs.append(channel)
                    channel_names.append(channel.name)
                else:
                    channel_errors.append(item)
            channel_list = [x.id for x in channel_objs]
            diff = set(channel_list) - set(guild_channel_list)
            if (not diff) and (not channel_errors):
                await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Region Command Channels enabled')))
                for channel in channel_objs:
                    ow = channel.overwrites_for(Meowth.user)
                    ow.send_messages = True
                    ow.read_messages = True
                    ow.manage_roles = True
                    try:
                        await channel.set_permissions(Meowth.user, overwrite=ow)
                    except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
                        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_('I couldn\'t set my own permissions in this channel. Please ensure I have the correct permissions in {channel} using **{prefix}get perms**.').format(prefix=ctx.prefix, channel=channel.mention)))
                config_dict_temp['regions']['command_channels'] = channel_list
                break
            else:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The channel list you provided doesn't match with your servers channels.\n\nThe following aren't in your server: **{invalid_channels}**\n\nPlease double check your channel list and resend your reponse.").format(invalid_channels=', '.join(channel_errors))))
                continue
    # set up roles
    new_region_roles = set([r['role'] for r in region_dict.values()])
    existing_region_dict = config_dict_temp['regions'].get('info', None)
    if existing_region_dict:
        existing_region_roles = set([r['role'] for r in existing_region_dict.values()])
        obsolete_roles = existing_region_roles - new_region_roles
        new_region_roles = new_region_roles - existing_region_roles
        # remove obsolete roles
        for role in obsolete_roles:
            temp_role = discord.utils.get(guild.roles, name=role)
            if temp_role:
                try:
                    await temp_role.delete(reason="Removed from region configuration")
                except discord.errors.HTTPException:
                    pass
    for role in new_region_roles:
        temp_role = discord.utils.get(guild.roles, name=role)
        if not temp_role:
            try:
                await guild.create_role(name=role, hoist=False, mentionable=True)
            except discord.errors.HTTPException:
                pass
    await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Region roles updated')))
    config_dict_temp['regions']['info'] = region_dict
    ctx.config_dict_temp = config_dict_temp
    return ctx

async def _get_listings(guild, owner, config_dict_temp):
    listing_dict = {}
    if config_dict_temp.get('regions', {}).get('enabled', None):
        region_names = list(config_dict_temp['regions']['info'].keys())
        await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("I can also provide listings per region that I will keep updated automatically as events are reported, updated, or expired. To get started, please provide a comma-separated list of channel names, one per region, matching the format of this list of regions:\n\n`{region_list}`\n\n**IMPORTANT** I recommend you set the permissions for each channel provided to allow only me to post to it. I will moderate each channel to remove other messages, but it will save me some work!").format(region_list=', '.join(region_names))).set_author(name=_('Listing Channels'), icon_url=Meowth.user.avatar_url))
        while True:
            listing_channels = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
            listing_channels = listing_channels.content.lower()
            if listing_channels == 'n':
                listing_dict['enabled'] = False
                await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Listing disabled')))
                break
            elif listing_channels == 'cancel':
                await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                return None
            else:
                listing_dict['enabled'] = True
                channel_dict = {}
                channel_list = [x.strip() for x in listing_channels.split(',')]
                guild_channel_list = [channel.id for channel in guild.text_channels]
                channel_objs = []
                channel_names = []
                channel_errors = []
                for item in channel_list:
                    channel = None
                    if item.isdigit():
                        channel = discord.utils.get(guild.text_channels, id=int(item))
                    if not channel:
                        name = sanitize_name(item)
                        channel = discord.utils.get(guild.text_channels, name=name)
                    if channel:
                        channel_objs.append(channel)
                        channel_names.append(channel.name)
                    else:
                        channel_errors.append(item)
                if len(channel_objs) != len(region_names):
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The channel list you provided doesn't match with your region list.\n\nPlease provide a channel for each region in your region list:\n\n{region_list}").format(region_list=', '.join(region_names))))
                    continue
                diff = set([x.id for x in channel_objs]) - set(guild_channel_list)
                if (not diff) and (not channel_errors):
                    await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Listing Channels enabled')))
                    for i, channel in enumerate(channel_objs):
                        ow = channel.overwrites_for(Meowth.user)
                        ow.send_messages = True
                        ow.read_messages = True
                        ow.manage_roles = True
                        try:
                            await channel.set_permissions(Meowth.user, overwrite = ow)
                        except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
                            await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_('I couldn\'t set my own permissions in this channel. Please ensure I have the correct permissions in {channel} using **{prefix}get perms**.').format(prefix=ctx.prefix, channel=channel.mention)))
                        channel_dict[region_names[i]] = {'id': channel.id, 'messages': []}
                    listing_dict['channels'] = channel_dict
                    break
                else:
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The channel list you provided doesn't match with your servers channels.\n\nThe following aren't in your server: **{invalid_channels}**\n\nPlease double check your channel list and resend your reponse.").format(invalid_channels=', '.join(channel_errors))))
                    continue
    else:
        await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("I can also provide a listing that I will keep updated automatically as events are reported, updated, or expired. To enable this, please provide a channel name where this listing should be shown.\n\n**IMPORTANT** I recommend you set the permissions for this channel to allow only me to post to it. I will moderate the channel to remove other messages, but it will save me some work!")).set_author(name=_('Listing Channels'), icon_url=Meowth.user.avatar_url))
        while True:
            listing_channel = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
            listing_channel = listing_channel.content.lower()
            if listing_channel == 'n':
                listing_dict['enabled'] = False
                await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Listing disabled')))
                break
            elif listing_channel == 'cancel':
                await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                return None
            else:
                listing_dict['enabled'] = True
                channel_dict = {}
                channel_list = [(listing_channels.split(',')[0]).strip()]
                guild_channel_list = [channel.id for channel in guild.text_channels]
                channel_objs = []
                channel_names = []
                channel_errors = []
                for item in channel_list:
                    channel = None
                    if item.isdigit():
                        channel = discord.utils.get(guild.text_channels, id=int(item))
                    if not channel:
                        name = sanitize_name(item)
                        channel = discord.utils.get(guild.text_channels, name=name)
                    if channel:
                        channel_objs.append(channel)
                        channel_names.append(channel.name)
                    else:
                        channel_errors.append(item)
                diff = set([x.id for x in channel_objs]) - set(guild_channel_list)
                if (not diff) and (not channel_errors):
                    await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Listing Channel enabled')))
                    for i, channel in enumerate(channel_objs):
                        ow = channel.overwrites_for(Meowth.user)
                        ow.send_messages = True
                        ow.read_messages = True
                        ow.manage_roles = True
                        try:
                            await channel.set_permissions(Meowth.user, overwrite = ow)
                        except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
                            await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_('I couldn\'t set my own permissions in this channel. Please ensure I have the correct permissions in {channel} using **{prefix}get perms**.').format(prefix=ctx.prefix, channel=channel.mention)))
                    listing_dict['channel'] = {'id': channel_objs[0].id, 'messages': []}
                    break
                else:
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The channel you provided doesn't match with your servers channels.\n\nPlease double check your channel and resend your reponse.")))
                    continue
    return listing_dict

@configure.command()
async def raid(ctx):
    """!raid reporting settings"""
    return await _check_sessions_and_invoke(ctx, _configure_raid)

async def _configure_raid(ctx):
    guild = ctx.message.guild
    owner = ctx.message.author
    config_dict_temp = getattr(ctx, 'config_dict_temp',copy.deepcopy(guild_dict[guild.id]['configure_dict']))
    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("Raid Reporting allows users to report active raids with **!raid** or raid eggs with **!raidegg**. Pokemon raid reports are contained within one or more channels. Each channel will be able to represent different areas/communities. I'll need you to provide a list of channels in your server you will allow reports from in this format: `channel-name, channel-name, channel-name`\n\nExample: `kansas-city-raids, hull-raids, sydney-raids`\n\nIf you do not require raid or raid egg reporting, you may want to disable this function.\n\nRespond with: **N** to disable, or the **channel-name** list to enable, each seperated with a comma and space:")).set_author(name=_('Raid Reporting Channels'), icon_url=Meowth.user.avatar_url))
    citychannel_dict = {}
    while True:
        citychannels = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
        if citychannels.content.lower() == 'n':
            config_dict_temp['raid']['enabled'] = False
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Raid Reporting disabled')))
            break
        elif citychannels.content.lower() == 'cancel':
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
            return None
        else:
            config_dict_temp['raid']['enabled'] = True
            citychannel_list = citychannels.content.lower().split(',')
            citychannel_list = [x.strip() for x in citychannel_list]
            guild_channel_list = []
            for channel in guild.text_channels:
                guild_channel_list.append(channel.id)
            citychannel_objs = []
            citychannel_names = []
            citychannel_errors = []
            for item in citychannel_list:
                channel = None
                if item.isdigit():
                    channel = discord.utils.get(guild.text_channels, id=int(item))
                if not channel:
                    item = re.sub('[^a-zA-Z0-9 _\\-]+', '', item)
                    item = item.replace(" ","-")
                    name = await letter_case(guild.text_channels, item.lower())
                    channel = discord.utils.get(guild.text_channels, name=name)
                if channel:
                    citychannel_objs.append(channel)
                    citychannel_names.append(channel.name)
                else:
                    citychannel_errors.append(item)
            citychannel_list = [x.id for x in citychannel_objs]
            diff = set(citychannel_list) - set(guild_channel_list)
            if (not diff) and (not citychannel_errors):
                await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Raid Reporting Channels enabled')))
                for channel in citychannel_objs:
                    ow = channel.overwrites_for(Meowth.user)
                    ow.send_messages = True
                    ow.read_messages = True
                    ow.manage_roles = True
                    try:
                        await channel.set_permissions(Meowth.user, overwrite = ow)
                    except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
                        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_('I couldn\'t set my own permissions in this channel. Please ensure I have the correct permissions in {channel} using **{prefix}get perms**.').format(prefix=ctx.prefix, channel=channel.mention)))
                break
            else:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The channel list you provided doesn't match with your servers channels.\n\nThe following aren't in your server: **{invalid_channels}**\n\nPlease double check your channel list and resend your reponse.").format(invalid_channels=', '.join(citychannel_errors))))
                continue
    if config_dict_temp['raid']['enabled']:
        if config_dict_temp.get('regions', {}).get('enabled', None):
            region_names = [name for name in config_dict_temp['regions']['info'].keys()]
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('For each report, I generate Google Maps links to give people directions to the raid or egg! To do this, I need to know which region each report channel represents using the region names as previously configured (see below), to ensure we get the right location in the map. For each report channel you provided, I will need its corresponding region using only letters and spaces, with each region seperated by a comma and space.\n\nExample: `kanto, johto, sinnoh`\n\nEach location will have to be in the same order as you provided the channels in the previous question.\n\nRespond with: **region name, region name, region name** each matching the order of the previous channel list below.')).set_author(name=_('Raid Reporting Regions'), icon_url=Meowth.user.avatar_url))
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{citychannel_list}').format(citychannel_list=citychannels.content.lower()[:2000])).set_author(name=_('Entered Channels'), icon_url=Meowth.user.avatar_url))
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{region_names}').format(region_names=(', '.join(region_names)).lower()[:2000])).set_author(name=_('Entered Regions'), icon_url=Meowth.user.avatar_url))
            while True:
                regions = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
                regions = regions.content.lower().strip()
                if regions == 'cancel':
                    await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                    return None
                region_list = [x.strip() for x in regions.split(',')]
                if len(region_list) == len(citychannel_list):
                    for i in range(len(citychannel_list)):
                        citychannel_dict[citychannel_list[i]] = region_list[i]
                    break
                else:
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The number of regions doesn't match the number of channels you gave me earlier!\n\nI'll show you the two lists to compare:\n\n{channellist}\n{regionlist}\n\nPlease double check that your regions match up with your provided channels and resend your response.").format(channellist=', '.join(citychannel_names), regionlist=', '.join(region_list))))
                    continue
        else:
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('For each report, I generate Google Maps links to give people directions to the raid or egg! To do this, I need to know which suburb/town/region each report channel represents, to ensure we get the right location in the map. For each report channel you provided, I will need its corresponding general location using only letters and spaces, with each location seperated by a comma and space.\n\nExample: `kansas city mo, hull uk, sydney nsw australia`\n\nEach location will have to be in the same order as you provided the channels in the previous question.\n\nRespond with: **location info, location info, location info** each matching the order of the previous channel list below.')).set_author(name=_('Raid Reporting Locations'), icon_url=Meowth.user.avatar_url))
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{citychannel_list}').format(citychannel_list=citychannels.content.lower()[:2000])).set_author(name=_('Entered Channels'), icon_url=Meowth.user.avatar_url))
            while True:
                cities = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
                if cities.content.lower() == 'cancel':
                    await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                    return None
                city_list = cities.content.split(',')
                city_list = [x.strip() for x in city_list]
                if len(city_list) == len(citychannel_list):
                    for i in range(len(citychannel_list)):
                        citychannel_dict[citychannel_list[i]] = city_list[i]
                    break
                else:
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The number of cities doesn't match the number of channels you gave me earlier!\n\nI'll show you the two lists to compare:\n\n{channellist}\n{citylist}\n\nPlease double check that your locations match up with your provided channels and resend your response.").format(channellist=', '.join(citychannel_names), citylist=', '.join(city_list))))
                    continue
        config_dict_temp['raid']['report_channels'] = citychannel_dict
        await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Raid Reporting Locations are set')))
        await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("How would you like me to categorize the raid channels I create? Your options are:\n\n**none** - If you don't want them categorized\n**same** - If you want them in the same category as the reporting channel\n**region** - If you want them categorized by region\n**level** - If you want them categorized by level.")).set_author(name=_('Raid Reporting Categories'), icon_url=Meowth.user.avatar_url))
        while True:
            guild = Meowth.get_guild(guild.id)
            guild_catlist = []
            for cat in guild.categories:
                guild_catlist.append(cat.id)
            category_dict = {}
            categories = await Meowth.wait_for('message', check=lambda message: message.guild == None and message.author == owner)
            if categories.content.lower() == 'cancel':
                await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                return None
            elif categories.content.lower() == 'none':
                config_dict_temp['raid']['categories'] = None
                break
            elif categories.content.lower() == 'same':
                config_dict_temp['raid']['categories'] = 'same'
                break
            elif categories.content.lower() == 'region':
                while True:
                    guild = Meowth.get_guild(guild.id)
                    guild_catlist = []
                    for cat in guild.categories:
                        guild_catlist.append(cat.id)
                    config_dict_temp['raid']['categories'] = 'region'
                    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(),description=_("In the same order as they appear below, please give the names of the categories you would like raids reported in each channel to appear in. You do not need to use different categories for each channel, but they do need to be pre-existing categories. Separate each category name with a comma. Response can be either category name or ID.\n\nExample: `kansas city, hull, 1231231241561337813`\n\nYou have configured the following channels as raid reporting channels.")).set_author(name=_('Raid Reporting Categories'), icon_url=Meowth.user.avatar_url))
                    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{citychannel_list}').format(citychannel_list=citychannels.content.lower()[:2000])).set_author(name=_('Entered Channels'), icon_url=Meowth.user.avatar_url))
                    regioncats = await Meowth.wait_for('message', check=lambda message: message.guild == None and message.author == owner)
                    if regioncats.content.lower() == "cancel":
                        await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                        return None
                    regioncat_list = regioncats.content.split(',')
                    regioncat_list = [x.strip() for x in regioncat_list]
                    regioncat_ids = []
                    regioncat_names = []
                    regioncat_errors = []
                    for item in regioncat_list:
                        category = None
                        if item.isdigit():
                            category = discord.utils.get(guild.categories, id=int(item))
                        if not category:
                            name = await letter_case(guild.categories, item.lower())
                            category = discord.utils.get(guild.categories, name=name)
                        if category:
                            regioncat_ids.append(category.id)
                            regioncat_names.append(category.name)
                        else:
                            regioncat_errors.append(item)
                    regioncat_list = regioncat_ids
                    if len(regioncat_list) == len(citychannel_list):
                        catdiff = set(regioncat_list) - set(guild_catlist)
                        if (not catdiff) and (not regioncat_errors):
                            for i in range(len(citychannel_list)):
                                category_dict[citychannel_list[i]] = regioncat_list[i]
                            break
                        else:
                            msg = _("The category list you provided doesn't match with your server's categories.")
                            if regioncat_errors:
                                msg += _("\n\nThe following aren't in your server: **{invalid_categories}**").format(invalid_categories=', '.join(regioncat_errors))
                            msg += _("\n\nPlease double check your category list and resend your response. If you just made these categories, try again.")
                            await owner.send(embed=discord.Embed(colour=discord.Colour.orange(),description=msg))
                            continue
                    else:
                        msg = _("The number of categories I found in your server doesn't match the number of channels you gave me earlier!\n\nI'll show you the two lists to compare:\n\n**Matched Channels:** {channellist}\n**Matched Categories:** {catlist}\n\nPlease double check that your categories match up with your provided channels and resend your response.").format(channellist=', '.join(citychannel_names), catlist=', '.join(regioncat_names) if len(regioncat_list)>0 else "None")
                        if regioncat_errors:
                            msg += _("\n\nThe following aren't in your server: **{invalid_categories}**").format(invalid_categories=', '.join(regioncat_errors))
                        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=msg))
                        continue
                    break
            elif categories.content.lower() == 'level':
                config_dict_temp['raid']['categories'] = 'level'
                while True:
                    guild = Meowth.get_guild(guild.id)
                    guild_catlist = []
                    for cat in guild.categories:
                        guild_catlist.append(cat.id)
                    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(),description=_("Pokemon Go currently has five levels of raids. Please provide the names of the categories you would like each level of raid to appear in. Use the following order: 1, 2, 3, 4, 5 \n\nYou do not need to use different categories for each level, but they do need to be pre-existing categories. Separate each category name with a comma. Response can be either category name or ID.\n\nExample: `level 1-3, level 1-3, level 1-3, level 4, 1231231241561337813`")).set_author(name=_('Raid Reporting Categories'), icon_url=Meowth.user.avatar_url))
                    levelcats = await Meowth.wait_for('message', check=lambda message: message.guild == None and message.author == owner)
                    if levelcats.content.lower() == "cancel":
                        await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                        return None
                    levelcat_list = levelcats.content.split(',')
                    levelcat_list = [x.strip() for x in levelcat_list]
                    levelcat_ids = []
                    levelcat_names = []
                    levelcat_errors = []
                    for item in levelcat_list:
                        category = None
                        if item.isdigit():
                            category = discord.utils.get(guild.categories, id=int(item))
                        if not category:
                            name = await letter_case(guild.categories, item.lower())
                            category = discord.utils.get(guild.categories, name=name)
                        if category:
                            levelcat_ids.append(category.id)
                            levelcat_names.append(category.name)
                        else:
                            levelcat_errors.append(item)
                    levelcat_list = levelcat_ids
                    if len(levelcat_list) == 5:
                        catdiff = set(levelcat_list) - set(guild_catlist)
                        if (not catdiff) and (not levelcat_errors):
                            level_list = ["1",'2','3','4','5']
                            for i in range(5):
                                category_dict[level_list[i]] = levelcat_list[i]
                            break
                        else:
                            msg = _("The category list you provided doesn't match with your server's categories.")
                            if levelcat_errors:
                                msg += _("\n\nThe following aren't in your server: **{invalid_categories}**").format(invalid_categories=', '.join(levelcat_errors))
                            msg += _("\n\nPlease double check your category list and resend your response. If you just made these categories, try again.")
                            await owner.send(embed=discord.Embed(colour=discord.Colour.orange(),description=msg))
                            continue
                    else:
                        msg = _("The number of categories I found in your server doesn't match the number of raid levels! Make sure you give me exactly six categories, one for each level of raid. You can use the same category for multiple levels if you want, but I need to see six category names.\n\n**Matched Categories:** {catlist}\n\nPlease double check your categories.").format(catlist=', '.join(levelcat_names) if len(levelcat_list)>0 else "None")
                        if levelcat_errors:
                            msg += _("\n\nThe following aren't in your server: **{invalid_categories}**").format(invalid_categories=', '.join(levelcat_errors))
                        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=msg))
                        continue
            else:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(),description=_("Sorry, I didn't understand your answer! Try again.")))
                continue
            break
        await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Raid Categories are set')))
        await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("For each of the regions with raid reporting enabled, please provide the region names\
                for each region you would like to have individual raid channels created. \nIf you would like this enabled for all regions, reply with **all**. \nIf you would like it disabled for\
                all regions reply with **none**.\n\nOtherwise, simply provide the region names like so:\n\
                `Johto, Kanto, Hoenn`")).set_author(name=_('Raid Reporting Categories'), icon_url=Meowth.user.avatar_url))
        config_dict_temp['raid']['raid_channels'] = {}
        region_names = [name for name in config_dict_temp['regions']['info'].keys()]
        while True:
            categories = await Meowth.wait_for('message', check=lambda message: message.guild == None and message.author == owner)
            categories = categories.content.lower()
            if categories == "cancel":
                await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                return None
            if categories == "all":
                for region in region_names:
                    config_dict_temp['raid']['raid_channels'][region] = True
                break
            elif categories == "none":
                for region in region_names:
                    config_dict_temp['raid']['raid_channels'][region] = False
                break
            else:
                entered_regions = categories.split(',')
                entered_regions = [r.strip() for r in entered_regions]
                error_set = set(entered_regions) - set(region_names)
                if len(error_set) > 0:
                    msg = ("The following regions you provided are not in your server's region list: **{invalid}**").format(invalid=', '.join(error_set))
                    msg += "\n\nPlease enter the regions that will have raid channels enabled."
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(),description=msg))
                    continue
                for region in entered_regions:
                    if region in region_names:
                        config_dict_temp['raid']['raid_channels'][region] = True
                disabled_region_set = set(region_names) - set(entered_regions)
                for region in disabled_region_set:
                    config_dict_temp['raid']['raid_channels'][region] = False
                break
        config_dict_temp['raid']['category_dict'] = category_dict
        config_dict_temp['raid']['listings'] = await _get_listings(guild, owner, config_dict_temp)
    ctx.config_dict_temp = config_dict_temp
    return ctx

@configure.command()
async def exraid(ctx):
    """!exraid reporting settings"""
    return await _check_sessions_and_invoke(ctx, _configure_exraid)

async def _configure_exraid(ctx):
    guild = ctx.message.guild
    owner = ctx.message.author
    config_dict_temp = getattr(ctx, 'config_dict_temp',copy.deepcopy(guild_dict[guild.id]['configure_dict']))
    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("EX Raid Reporting allows users to report EX raids with **!exraid**. Pokemon EX raid reports are contained within one or more channels. Each channel will be able to represent different areas/communities. I'll need you to provide a list of channels in your server you will allow reports from in this format: `channel-name, channel-name, channel-name`\n\nExample: `kansas-city-raids, hull-raids, sydney-raids`\n\nIf you do not require EX raid reporting, you may want to disable this function.\n\nRespond with: **N** to disable, or the **channel-name** list to enable, each seperated with a comma and space:")).set_author(name=_('EX Raid Reporting Channels'), icon_url=Meowth.user.avatar_url))
    citychannel_dict = {}
    while True:
        citychannels = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
        if citychannels.content.lower() == 'n':
            config_dict_temp['exraid']['enabled'] = False
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('EX Raid Reporting disabled')))
            break
        elif citychannels.content.lower() == 'cancel':
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
            return None
        else:
            config_dict_temp['exraid']['enabled'] = True
            citychannel_list = citychannels.content.lower().split(',')
            citychannel_list = [x.strip() for x in citychannel_list]
            guild_channel_list = []
            for channel in guild.text_channels:
                guild_channel_list.append(channel.id)
            citychannel_objs = []
            citychannel_names = []
            citychannel_errors = []
            for item in citychannel_list:
                channel = None
                if item.isdigit():
                    channel = discord.utils.get(guild.text_channels, id=int(item))
                if not channel:
                    item = re.sub('[^a-zA-Z0-9 _\\-]+', '', item)
                    item = item.replace(" ","-")
                    name = await letter_case(guild.text_channels, item.lower())
                    channel = discord.utils.get(guild.text_channels, name=name)
                if channel:
                    citychannel_objs.append(channel)
                    citychannel_names.append(channel.name)
                else:
                    citychannel_errors.append(item)
            citychannel_list = [x.id for x in citychannel_objs]
            diff = set(citychannel_list) - set(guild_channel_list)
            if (not diff) and (not citychannel_errors):
                await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('EX Raid Reporting Channels enabled')))
                for channel in citychannel_objs:
                    ow = channel.overwrites_for(Meowth.user)
                    ow.send_messages = True
                    ow.read_messages = True
                    ow.manage_roles = True
                    try:
                        await channel.set_permissions(Meowth.user, overwrite = ow)
                    except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
                        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_('I couldn\'t set my own permissions in this channel. Please ensure I have the correct permissions in {channel} using **{prefix}get perms**.').format(prefix=ctx.prefix, channel=channel.mention)))
                break
            else:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The channel list you provided doesn't match with your servers channels.\n\nThe following aren't in your server: **{invalid_channels}**\n\nPlease double check your channel list and resend your reponse.").format(invalid_channels=', '.join(citychannel_errors))))
                continue
    if config_dict_temp['exraid']['enabled']:
        if config_dict_temp.get('regions', {}).get('enabled', None):
            region_names = [name for name in config_dict_temp['regions']['info'].keys()]
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('For each report, I generate Google Maps links to give people directions to the raid or egg! To do this, I need to know which region each report channel represents using the region names as previously configured (see below), to ensure we get the right location in the map. For each report channel you provided, I will need its corresponding region using only letters and spaces, with each region seperated by a comma and space.\n\nExample: `kanto, johto, sinnoh`\n\nEach location will have to be in the same order as you provided the channels in the previous question.\n\nRespond with: **region name, region name, region name** each matching the order of the previous channel list below.')).set_author(name=_('EX Raid Reporting Regions'), icon_url=Meowth.user.avatar_url))
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{citychannel_list}').format(citychannel_list=citychannels.content.lower()[:2000])).set_author(name=_('Entered Channels'), icon_url=Meowth.user.avatar_url))
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{region_names}').format(region_names=region_names[:2000])).set_author(name=_('Entered Regions'), icon_url=Meowth.user.avatar_url))
            while True:
                regions = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
                regions = regions.content.lower().strip()
                if regions == 'cancel':
                    await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                    return None
                region_list = [x.strip() for x in regions.split(',')]
                if len(region_list) == len(citychannel_list):
                    for i in range(len(citychannel_list)):
                        citychannel_dict[citychannel_list[i]] = region_list[i]
                    break
                else:
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The number of regions doesn't match the number of channels you gave me earlier!\n\nI'll show you the two lists to compare:\n\n{channellist}\n{regionlist}\n\nPlease double check that your regions match up with your provided channels and resend your response.").format(channellist=', '.join(citychannel_names), regionlist=', '.join(region_list))))
                    continue
        else:
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('For each report, I generate Google Maps links to give people directions to EX raids! To do this, I need to know which suburb/town/region each report channel represents, to ensure we get the right location in the map. For each report channel you provided, I will need its corresponding general location using only letters and spaces, with each location seperated by a comma and space.\n\nExample: `kansas city mo, hull uk, sydney nsw australia`\n\nEach location will have to be in the same order as you provided the channels in the previous question.\n\nRespond with: **location info, location info, location info** each matching the order of the previous channel list below.')).set_author(name=_('EX Raid Reporting Locations'), icon_url=Meowth.user.avatar_url))
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{citychannel_list}').format(citychannel_list=citychannels.content.lower()[:2000])).set_author(name=_('Entered Channels'), icon_url=Meowth.user.avatar_url))
            while True:
                cities = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
                if cities.content.lower() == 'cancel':
                    await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                    return None
                city_list = cities.content.split(',')
                city_list = [x.strip() for x in city_list]
                if len(city_list) == len(citychannel_list):
                    for i in range(len(citychannel_list)):
                        citychannel_dict[citychannel_list[i]] = city_list[i]
                    break
                else:
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The number of cities doesn't match the number of channels you gave me earlier!\n\nI'll show you the two lists to compare:\n\n{channellist}\n{citylist}\n\nPlease double check that your locations match up with your provided channels and resend your response.").format(channellist=', '.join(citychannel_names), citylist=', '.join(city_list))))
                    continue
        config_dict_temp['exraid']['report_channels'] = citychannel_dict
        await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('EX Raid Reporting Locations are set')))
        await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("How would you like me to categorize the EX raid channels I create? Your options are:\n\n**none** - If you don't want them categorized\n**same** - If you want them in the same category as the reporting channel\n**other** - If you want them categorized in a provided category name or ID")).set_author(name=_('EX Raid Reporting Categories'), icon_url=Meowth.user.avatar_url))
        while True:
            guild = Meowth.get_guild(guild.id)
            guild_catlist = []
            for cat in guild.categories:
                guild_catlist.append(cat.id)
            category_dict = {}
            categories = await Meowth.wait_for('message', check=lambda message: message.guild == None and message.author == owner)
            if categories.content.lower() == 'cancel':
                await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                return None
            elif categories.content.lower() == 'none':
                config_dict_temp['exraid']['categories'] = None
                break
            elif categories.content.lower() == 'same':
                config_dict_temp['exraid']['categories'] = 'same'
                break
            elif categories.content.lower() == 'other':
                while True:
                    guild = Meowth.get_guild(guild.id)
                    guild_catlist = []
                    for cat in guild.categories:
                        guild_catlist.append(cat.id)
                    config_dict_temp['exraid']['categories'] = 'region'
                    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(),description=_("In the same order as they appear below, please give the names of the categories you would like raids reported in each channel to appear in. You do not need to use different categories for each channel, but they do need to be pre-existing categories. Separate each category name with a comma. Response can be either category name or ID.\n\nExample: `kansas city, hull, 1231231241561337813`\n\nYou have configured the following channels as EX raid reporting channels.")).set_author(name=_('EX Raid Reporting Categories'), icon_url=Meowth.user.avatar_url))
                    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{citychannel_list}').format(citychannel_list=citychannels.content.lower()[:2000])).set_author(name=_('Entered Channels'), icon_url=Meowth.user.avatar_url))
                    regioncats = await Meowth.wait_for('message', check=lambda message: message.guild == None and message.author == owner)
                    if regioncats.content.lower() == "cancel":
                        await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                        return None
                    regioncat_list = regioncats.content.split(',')
                    regioncat_list = [x.strip() for x in regioncat_list]
                    regioncat_ids = []
                    regioncat_names = []
                    regioncat_errors = []
                    for item in regioncat_list:
                        category = None
                        if item.isdigit():
                            category = discord.utils.get(guild.categories, id=int(item))
                        if not category:
                            name = await letter_case(guild.categories, item.lower())
                            category = discord.utils.get(guild.categories, name=name)
                        if category:
                            regioncat_ids.append(category.id)
                            regioncat_names.append(category.name)
                        else:
                            regioncat_errors.append(item)
                    regioncat_list = regioncat_ids
                    if len(regioncat_list) == len(citychannel_list):
                        catdiff = set(regioncat_list) - set(guild_catlist)
                        if (not catdiff) and (not regioncat_errors):
                            for i in range(len(citychannel_list)):
                                category_dict[citychannel_list[i]] = regioncat_list[i]
                            break
                        else:
                            msg = _("The category list you provided doesn't match with your server's categories.")
                            if regioncat_errors:
                                msg += _("\n\nThe following aren't in your server: **{invalid_categories}**").format(invalid_categories=', '.join(regioncat_errors))
                            msg += _("\n\nPlease double check your category list and resend your response. If you just made these categories, try again.")
                            await owner.send(embed=discord.Embed(colour=discord.Colour.orange(),description=msg))
                            continue
                    else:
                        msg = _("The number of categories I found in your server doesn't match the number of channels you gave me earlier!\n\nI'll show you the two lists to compare:\n\n**Matched Channels:** {channellist}\n**Matched Categories:** {catlist}\n\nPlease double check that your categories match up with your provided channels and resend your response.").format(channellist=', '.join(citychannel_names), catlist=', '.join(regioncat_names) if len(regioncat_list)>0 else "None")
                        if regioncat_errors:
                            msg += _("\n\nThe following aren't in your server: **{invalid_categories}**").format(invalid_categories=', '.join(regioncat_errors))
                        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=msg))
                        continue
                    break
            else:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(),description=_("Sorry, I didn't understand your answer! Try again.")))
                continue
            break
        await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('EX Raid Categories are set')))
        config_dict_temp['exraid']['category_dict'] = category_dict
        await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("Who do you want to be able to **see** the EX Raid channels? Your options are:\n\n**everyone** - To have everyone be able to see all reported EX Raids\n**same** - To only allow those with access to the reporting channel.")).set_author(name=_('EX Raid Channel Read Permissions'), icon_url=Meowth.user.avatar_url))
        while True:
            permsconfigset = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
            if permsconfigset.content.lower() == 'everyone':
                config_dict_temp['exraid']['permissions'] = "everyone"
                await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Everyone permission enabled')))
                break
            elif permsconfigset.content.lower() == 'same':
                config_dict_temp['exraid']['permissions'] = "same"
                await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Same permission enabled')))
                break
            elif permsconfigset.content.lower() == 'cancel':
                await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                return None
            else:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("I'm sorry I don't understand. Please reply with either **N** to disable, or **Y** to enable.")))
                continue
    ctx.config_dict_temp = config_dict_temp
    return ctx

@configure.command()
async def invite(ctx):
    """!invite command settings"""
    return await _check_sessions_and_invoke(ctx, _configure_invite)

async def _configure_invite(ctx):
    guild = ctx.message.guild
    owner = ctx.message.author
    config_dict_temp = getattr(ctx, 'config_dict_temp',copy.deepcopy(guild_dict[guild.id]['configure_dict']))
    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('Do you want access to EX raids controlled through members using the **!invite** command?\nIf enabled, members will have read-only permissions for all EX Raids until they use **!invite** to gain access. If disabled, EX Raids will inherit the permissions from their reporting channels.\n\nRespond with: **N** to disable, or **Y** to enable:')).set_author(name=_('Invite Configuration'), icon_url=Meowth.user.avatar_url))
    while True:
        inviteconfigset = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
        if inviteconfigset.content.lower() == 'y':
            config_dict_temp['invite']['enabled'] = True
            await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Invite Command enabled')))
            break
        elif inviteconfigset.content.lower() == 'n':
            config_dict_temp['invite']['enabled'] = False
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Invite Command disabled')))
            break
        elif inviteconfigset.content.lower() == 'cancel':
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
            return None
        else:
            await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("I'm sorry I don't understand. Please reply with either **N** to disable, or **Y** to enable.")))
            continue
    ctx.config_dict_temp = config_dict_temp
    return ctx

@configure.command()
async def counters(ctx):
    """Automatic counters settings"""
    return await _check_sessions_and_invoke(ctx, _configure_counters)

async def _configure_counters(ctx):
    guild = ctx.message.guild
    owner = ctx.message.author
    config_dict_temp = getattr(ctx, 'config_dict_temp',copy.deepcopy(guild_dict[guild.id]['configure_dict']))
    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('Do you want to generate an automatic counters list in newly created raid channels using PokeBattler?\nIf enabled, I will post a message containing the best counters for the raid boss in new raid channels. Users will still be able to use **!counters** to generate this list.\n\nRespond with: **N** to disable, or enable with a comma separated list of boss levels that you would like me to generate counters for. Example:`3,4,5,EX`')).set_author(name=_('Automatic Counters Configuration'), icon_url=Meowth.user.avatar_url))
    while True:
        countersconfigset = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
        if countersconfigset.content.lower() == 'n':
            config_dict_temp['counters']['enabled'] = False
            config_dict_temp['counters']['auto_levels'] = []
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Automatic Counters disabled')))
            break
        elif countersconfigset.content.lower() == 'cancel':
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
            return None
        else:
            raidlevel_list = countersconfigset.content.lower().split(',')
            raidlevel_list = [x.strip() for x in raidlevel_list]
            counterlevels = []
            for level in raidlevel_list:
                if level.isdigit() and (int(level) <= 5):
                    counterlevels.append(str(level))
                elif level == "ex":
                    counterlevels.append("EX")
            if len(counterlevels) > 0:
                config_dict_temp['counters']['enabled'] = True
                config_dict_temp['counters']['auto_levels'] = counterlevels
                await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Automatic Counter Levels set to: {levels}').format(levels=', '.join((str(x) for x in config_dict_temp['counters']['auto_levels'])))))
                break
            else:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("Please enter at least one level from 1 to EX separated by comma. Ex: `4,5,EX` or **N** to turn off automatic counters.")))
                continue
    ctx.config_dict_temp = config_dict_temp
    return ctx

@configure.command()
async def wild(ctx):
    """!wild reporting settings"""
    return await _check_sessions_and_invoke(ctx, _configure_wild)

async def _configure_wild(ctx):
    guild = ctx.message.guild
    owner = ctx.message.author
    config_dict_temp = getattr(ctx, 'config_dict_temp',copy.deepcopy(guild_dict[guild.id]['configure_dict']))
    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("Wild Reporting allows users to report wild spawns with **!wild**. Pokemon **wild** reports are contained within one or more channels. Each channel will be able to represent different areas/communities. I'll need you to provide a list of channels in your server you will allow reports from in this format: `channel-name, channel-name, channel-name`\n\nExample: `kansas-city-wilds, hull-wilds, sydney-wilds`\n\nIf you do not require **wild** reporting, you may want to disable this function.\n\nRespond with: **N** to disable, or the **channel-name** list to enable, each seperated with a comma and space:")).set_author(name=_('Wild Reporting Channels'), icon_url=Meowth.user.avatar_url))
    citychannel_dict = {}
    while True:
        citychannels = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
        if citychannels.content.lower() == 'n':
            config_dict_temp['wild']['enabled'] = False
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Wild Reporting disabled')))
            break
        elif citychannels.content.lower() == 'cancel':
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
            return None
        else:
            config_dict_temp['wild']['enabled'] = True
            citychannel_list = citychannels.content.lower().split(',')
            citychannel_list = [x.strip() for x in citychannel_list]
            guild_channel_list = []
            for channel in guild.text_channels:
                guild_channel_list.append(channel.id)
            citychannel_objs = []
            citychannel_names = []
            citychannel_errors = []
            for item in citychannel_list:
                channel = None
                if item.isdigit():
                    channel = discord.utils.get(guild.text_channels, id=int(item))
                if not channel:
                    item = re.sub('[^a-zA-Z0-9 _\\-]+', '', item)
                    item = item.replace(" ","-")
                    name = await letter_case(guild.text_channels, item.lower())
                    channel = discord.utils.get(guild.text_channels, name=name)
                if channel:
                    citychannel_objs.append(channel)
                    citychannel_names.append(channel.name)
                else:
                    citychannel_errors.append(item)
            citychannel_list = [x.id for x in citychannel_objs]
            diff = set(citychannel_list) - set(guild_channel_list)
            if (not diff) and (not citychannel_errors):
                await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Wild Reporting Channels enabled')))
                for channel in citychannel_objs:
                    ow = channel.overwrites_for(Meowth.user)
                    ow.send_messages = True
                    ow.read_messages = True
                    ow.manage_roles = True
                    try:
                        await channel.set_permissions(Meowth.user, overwrite = ow)
                    except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
                        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_('I couldn\'t set my own permissions in this channel. Please ensure I have the correct permissions in {channel} using **{prefix}get perms**.').format(prefix=ctx.prefix, channel=channel.mention)))
                break
            else:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The channel list you provided doesn't match with your servers channels.\n\nThe following aren't in your server: **{invalid_channels}**\n\nPlease double check your channel list and resend your reponse.").format(invalid_channels=', '.join(citychannel_errors))))
                continue
    if config_dict_temp['wild']['enabled']:
        if config_dict_temp.get('regions', {}).get('enabled', None):
            region_names = [name for name in config_dict_temp['regions']['info'].keys()]
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('For each report, I generate Google Maps links to give people directions to wild spawns! To do this, I need to know which region each report channel represents using the region names as previously configured (see below), to ensure we get the right location in the map. For each report channel you provided, I will need its corresponding region using only letters and spaces, with each region seperated by a comma and space.\n\nExample: `kanto, johto, sinnoh`\n\nEach location will have to be in the same order as you provided the channels in the previous question.\n\nRespond with: **region name, region name, region name** each matching the order of the previous channel list below.')).set_author(name=_('Wild Reporting Regions'), icon_url=Meowth.user.avatar_url))
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{citychannel_list}').format(citychannel_list=citychannels.content.lower()[:2000])).set_author(name=_('Entered Channels'), icon_url=Meowth.user.avatar_url))
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{region_names}').format(region_names=region_names[:2000])).set_author(name=_('Entered Regions'), icon_url=Meowth.user.avatar_url))
            while True:
                regions = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
                regions = regions.content.lower().strip()
                if regions == 'cancel':
                    await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                    return None
                region_list = [x.strip() for x in regions.split(',')]
                if len(region_list) == len(citychannel_list):
                    for i in range(len(citychannel_list)):
                        citychannel_dict[citychannel_list[i]] = region_list[i]
                    break
                else:
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The number of regions doesn't match the number of channels you gave me earlier!\n\nI'll show you the two lists to compare:\n\n{channellist}\n{regionlist}\n\nPlease double check that your regions match up with your provided channels and resend your response.").format(channellist=', '.join(citychannel_names), regionlist=', '.join(region_list))))
                    continue
        else:
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('For each report, I generate Google Maps links to give people directions to wild spawns! To do this, I need to know which suburb/town/region each report channel represents, to ensure we get the right location in the map. For each report channel you provided, I will need its corresponding general location using only letters and spaces, with each location seperated by a comma and space.\n\nExample: `kansas city mo, hull uk, sydney nsw australia`\n\nEach location will have to be in the same order as you provided the channels in the previous question.\n\nRespond with: **location info, location info, location info** each matching the order of the previous channel list below.')).set_author(name=_('Wild Reporting Locations'), icon_url=Meowth.user.avatar_url))
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{citychannel_list}').format(citychannel_list=citychannels.content.lower()[:2000])).set_author(name=_('Entered Channels'), icon_url=Meowth.user.avatar_url))
            while True:
                cities = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
                if cities.content.lower() == 'cancel':
                    await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                    return None
                city_list = cities.content.split(',')
                city_list = [x.strip() for x in city_list]
                if len(city_list) == len(citychannel_list):
                    for i in range(len(citychannel_list)):
                        citychannel_dict[citychannel_list[i]] = city_list[i]
                    break
                else:
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The number of cities doesn't match the number of channels you gave me earlier!\n\nI'll show you the two lists to compare:\n\n{channellist}\n{citylist}\n\nPlease double check that your locations match up with your provided channels and resend your response.").format(channellist=', '.join(citychannel_names), citylist=', '.join(city_list))))
                    continue
        config_dict_temp['wild']['report_channels'] = citychannel_dict
        config_dict_temp['wild']['listings'] = await _get_listings(guild, owner, config_dict_temp)
        await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Wild Reporting Locations are set')))
    ctx.config_dict_temp = config_dict_temp
    return ctx

@configure.command()
async def research(ctx):
    """!research reporting settings"""
    return await _check_sessions_and_invoke(ctx, _configure_research)

async def _configure_research(ctx):
    guild = ctx.message.guild
    owner = ctx.message.author
    config_dict_temp = getattr(ctx, 'config_dict_temp',copy.deepcopy(guild_dict[guild.id]['configure_dict']))
    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("Research Reporting allows users to report field research with **!research**. Pokemon **research** reports are contained within one or more channels. Each channel will be able to represent different areas/communities. I'll need you to provide a list of channels in your server you will allow reports from in this format: `channel-name, channel-name, channel-name`\n\nExample: `kansas-city-research, hull-research, sydney-research`\n\nIf you do not require **research** reporting, you may want to disable this function.\n\nRespond with: **N** to disable, or the **channel-name** list to enable, each seperated with a comma and space:")).set_author(name=_('Research Reporting Channels'), icon_url=Meowth.user.avatar_url))
    citychannel_dict = {}
    while True:
        citychannels = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
        if citychannels.content.lower() == 'n':
            config_dict_temp['research']['enabled'] = False
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Research Reporting disabled')))
            break
        elif citychannels.content.lower() == 'cancel':
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
            return None
        else:
            config_dict_temp['research']['enabled'] = True
            citychannel_list = citychannels.content.lower().split(',')
            citychannel_list = [x.strip() for x in citychannel_list]
            guild_channel_list = []
            for channel in guild.text_channels:
                guild_channel_list.append(channel.id)
            citychannel_objs = []
            citychannel_names = []
            citychannel_errors = []
            for item in citychannel_list:
                channel = None
                if item.isdigit():
                    channel = discord.utils.get(guild.text_channels, id=int(item))
                if not channel:
                    item = re.sub('[^a-zA-Z0-9 _\\-]+', '', item)
                    item = item.replace(" ","-")
                    name = await letter_case(guild.text_channels, item.lower())
                    channel = discord.utils.get(guild.text_channels, name=name)
                if channel:
                    citychannel_objs.append(channel)
                    citychannel_names.append(channel.name)
                else:
                    citychannel_errors.append(item)
            citychannel_list = [x.id for x in citychannel_objs]
            diff = set(citychannel_list) - set(guild_channel_list)
            if (not diff) and (not citychannel_errors):
                await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Research Reporting Channels enabled')))
                for channel in citychannel_objs:
                    ow = channel.overwrites_for(Meowth.user)
                    ow.send_messages = True
                    ow.read_messages = True
                    ow.manage_roles = True
                    try:
                        await channel.set_permissions(Meowth.user, overwrite = ow)
                    except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
                        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_('I couldn\'t set my own permissions in this channel. Please ensure I have the correct permissions in {channel} using **{prefix}get perms**.').format(prefix=ctx.prefix, channel=channel.mention)))
                break
            else:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The channel list you provided doesn't match with your servers channels.\n\nThe following aren't in your server: **{invalid_channels}**\n\nPlease double check your channel list and resend your reponse.").format(invalid_channels=', '.join(citychannel_errors))))
                continue
    if config_dict_temp['research']['enabled']:
        if config_dict_temp.get('regions', {}).get('enabled', None):
            region_names = [name for name in config_dict_temp['regions']['info'].keys()]
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('For each report, I generate Google Maps links to give people directions to the field research! To do this, I need to know which region each report channel represents using the region names as previously configured (see below), to ensure we get the right location in the map. For each report channel you provided, I will need its corresponding region using only letters and spaces, with each region seperated by a comma and space.\n\nExample: `kanto, johto, sinnoh`\n\nEach location will have to be in the same order as you provided the channels in the previous question.\n\nRespond with: **region name, region name, region name** each matching the order of the previous channel list below.')).set_author(name=_('Research Reporting Regions'), icon_url=Meowth.user.avatar_url))
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{citychannel_list}').format(citychannel_list=citychannels.content.lower()[:2000])).set_author(name=_('Entered Channels'), icon_url=Meowth.user.avatar_url))
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{region_names}').format(region_names=region_names[:2000])).set_author(name=_('Entered Regions'), icon_url=Meowth.user.avatar_url))
            while True:
                regions = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
                regions = regions.content.lower().strip()
                if regions == 'cancel':
                    await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                    return None
                region_list = [x.strip() for x in regions.split(',')]
                if len(region_list) == len(citychannel_list):
                    for i in range(len(citychannel_list)):
                        citychannel_dict[citychannel_list[i]] = region_list[i]
                    break
                else:
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The number of regions doesn't match the number of channels you gave me earlier!\n\nI'll show you the two lists to compare:\n\n{channellist}\n{regionlist}\n\nPlease double check that your regions match up with your provided channels and resend your response.").format(channellist=', '.join(citychannel_names), regionlist=', '.join(region_list))))
                    continue
        else:
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('For each report, I generate Google Maps links to give people directions to field research! To do this, I need to know which suburb/town/region each report channel represents, to ensure we get the right location in the map. For each report channel you provided, I will need its corresponding general location using only letters and spaces, with each location seperated by a comma and space.\n\nExample: `kansas city mo, hull uk, sydney nsw australia`\n\nEach location will have to be in the same order as you provided the channels in the previous question.\n\nRespond with: **location info, location info, location info** each matching the order of the previous channel list below.')).set_author(name=_('Research Reporting Locations'), icon_url=Meowth.user.avatar_url))
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{citychannel_list}').format(citychannel_list=citychannels.content.lower()[:2000])).set_author(name=_('Entered Channels'), icon_url=Meowth.user.avatar_url))
            while True:
                cities = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
                if cities.content.lower() == 'cancel':
                    await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                    return None
                city_list = cities.content.split(',')
                city_list = [x.strip() for x in city_list]
                if len(city_list) == len(citychannel_list):
                    for i in range(len(citychannel_list)):
                        citychannel_dict[citychannel_list[i]] = city_list[i]
                    break
                else:
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The number of cities doesn't match the number of channels you gave me earlier!\n\nI'll show you the two lists to compare:\n\n{channellist}\n{citylist}\n\nPlease double check that your locations match up with your provided channels and resend your response.").format(channellist=', '.join(citychannel_names), citylist=', '.join(city_list))))
                    continue
        config_dict_temp['research']['report_channels'] = citychannel_dict
        config_dict_temp['research']['listings'] = await _get_listings(guild, owner, config_dict_temp)
        await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Research Reporting Locations are set')))
    ctx.config_dict_temp = config_dict_temp
    return ctx

@configure.command(aliases=['event'])
async def meetup(ctx):
    """!meetup reporting settings"""
    return await _check_sessions_and_invoke(ctx, _configure_meetup)

async def _configure_meetup(ctx):
    guild = ctx.message.guild
    owner = ctx.message.author
    config_dict_temp = getattr(ctx, 'config_dict_temp',copy.deepcopy(guild_dict[guild.id]['configure_dict']))
    config_dict_temp['meetup'] = {}
    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("Meetup Reporting allows users to report meetups with **!meetup** or **!event**. Meetup reports are contained within one or more channels. Each channel will be able to represent different areas/communities. I'll need you to provide a list of channels in your server you will allow reports from in this format: `channel-name, channel-name, channel-name`\n\nExample: `kansas-city-meetups, hull-meetups, sydney-meetups`\n\nIf you do not require meetup reporting, you may want to disable this function.\n\nRespond with: **N** to disable, or the **channel-name** list to enable, each seperated with a comma and space:")).set_author(name=_('Meetup Reporting Channels'), icon_url=Meowth.user.avatar_url))
    citychannel_dict = {}
    while True:
        citychannels = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
        if citychannels.content.lower() == 'n':
            config_dict_temp['meetup']['enabled'] = False
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Meetup Reporting disabled')))
            break
        elif citychannels.content.lower() == 'cancel':
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
            return None
        else:
            config_dict_temp['meetup']['enabled'] = True
            citychannel_list = citychannels.content.lower().split(',')
            citychannel_list = [x.strip() for x in citychannel_list]
            guild_channel_list = []
            for channel in guild.text_channels:
                guild_channel_list.append(channel.id)
            citychannel_objs = []
            citychannel_names = []
            citychannel_errors = []
            for item in citychannel_list:
                channel = None
                if item.isdigit():
                    channel = discord.utils.get(guild.text_channels, id=int(item))
                if not channel:
                    item = re.sub('[^a-zA-Z0-9 _\\-]+', '', item)
                    item = item.replace(" ","-")
                    name = await letter_case(guild.text_channels, item.lower())
                    channel = discord.utils.get(guild.text_channels, name=name)
                if channel:
                    citychannel_objs.append(channel)
                    citychannel_names.append(channel.name)
                else:
                    citychannel_errors.append(item)
            citychannel_list = [x.id for x in citychannel_objs]
            diff = set(citychannel_list) - set(guild_channel_list)
            if (not diff) and (not citychannel_errors):
                await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Meetup Reporting Channels enabled')))
                for channel in citychannel_objs:
                    ow = channel.overwrites_for(Meowth.user)
                    ow.send_messages = True
                    ow.read_messages = True
                    ow.manage_roles = True
                    try:
                        await channel.set_permissions(Meowth.user, overwrite = ow)
                    except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
                        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_('I couldn\'t set my own permissions in this channel. Please ensure I have the correct permissions in {channel} using **{prefix}get perms**.').format(prefix=ctx.prefix, channel=channel.mention)))
                break
            else:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The channel list you provided doesn't match with your servers channels.\n\nThe following aren't in your server: **{invalid_channels}**\n\nPlease double check your channel list and resend your reponse.").format(invalid_channels=', '.join(citychannel_errors))))
                continue
    if config_dict_temp['meetup']['enabled']:
        if config_dict_temp.get('regions', {}).get('enabled', None):
            region_names = [name for name in config_dict_temp['regions']['info'].keys()]
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('For each report, I generate Google Maps links to give people directions to the meetup! To do this, I need to know which region each report channel represents using the region names as previously configured (see below), to ensure we get the right location in the map. For each report channel you provided, I will need its corresponding region using only letters and spaces, with each region seperated by a comma and space.\n\nExample: `kanto, johto, sinnoh`\n\nEach location will have to be in the same order as you provided the channels in the previous question.\n\nRespond with: **region name, region name, region name** each matching the order of the previous channel list below.')).set_author(name=_('Meetup Reporting Regions'), icon_url=Meowth.user.avatar_url))
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{citychannel_list}').format(citychannel_list=citychannels.content.lower()[:2000])).set_author(name=_('Entered Channels'), icon_url=Meowth.user.avatar_url))
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{region_names}').format(region_names=region_names[:2000])).set_author(name=_('Entered Regions'), icon_url=Meowth.user.avatar_url))
            while True:
                regions = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
                regions = regions.content.lower().strip()
                if regions == 'cancel':
                    await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                    return None
                region_list = [x.strip() for x in regions.split(',')]
                if len(region_list) == len(citychannel_list):
                    for i in range(len(citychannel_list)):
                        citychannel_dict[citychannel_list[i]] = region_list[i]
                    break
                else:
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The number of regions doesn't match the number of channels you gave me earlier!\n\nI'll show you the two lists to compare:\n\n{channellist}\n{regionlist}\n\nPlease double check that your regions match up with your provided channels and resend your response.").format(channellist=', '.join(citychannel_names), regionlist=', '.join(region_list))))
                    continue
        else:
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('For each report, I generate Google Maps links to give people directions to meetups! To do this, I need to know which suburb/town/region each report channel represents, to ensure we get the right location in the map. For each report channel you provided, I will need its corresponding general location using only letters and spaces, with each location seperated by a comma and space.\n\nExample: `kansas city mo, hull uk, sydney nsw australia`\n\nEach location will have to be in the same order as you provided the channels in the previous question.\n\nRespond with: **location info, location info, location info** each matching the order of the previous channel list below.')).set_author(name=_('Meetup Reporting Locations'), icon_url=Meowth.user.avatar_url))
            await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{citychannel_list}').format(citychannel_list=citychannels.content.lower()[:2000])).set_author(name=_('Entered Channels'), icon_url=Meowth.user.avatar_url))
            while True:
                cities = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
                if cities.content.lower() == 'cancel':
                    await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                    return None
                city_list = cities.content.split(',')
                city_list = [x.strip() for x in city_list]
                if len(city_list) == len(citychannel_list):
                    for i in range(len(citychannel_list)):
                        citychannel_dict[citychannel_list[i]] = city_list[i]
                    break
                else:
                    await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The number of cities doesn't match the number of channels you gave me earlier!\n\nI'll show you the two lists to compare:\n\n{channellist}\n{citylist}\n\nPlease double check that your locations match up with your provided channels and resend your response.").format(channellist=', '.join(citychannel_names), citylist=', '.join(city_list))))
                    continue
        config_dict_temp['meetup']['report_channels'] = citychannel_dict
        await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Meetup Reporting Locations are set')))
        await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("How would you like me to categorize the meetup channels I create? Your options are:\n\n**none** - If you don't want them categorized\n**same** - If you want them in the same category as the reporting channel\n**other** - If you want them categorized in a provided category name or ID")).set_author(name=_('Meetup Reporting Categories'), icon_url=Meowth.user.avatar_url))
        while True:
            guild = Meowth.get_guild(guild.id)
            guild_catlist = []
            for cat in guild.categories:
                guild_catlist.append(cat.id)
            category_dict = {}
            categories = await Meowth.wait_for('message', check=lambda message: message.guild == None and message.author == owner)
            if categories.content.lower() == 'cancel':
                await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                return None
            elif categories.content.lower() == 'none':
                config_dict_temp['meetup']['categories'] = None
                break
            elif categories.content.lower() == 'same':
                config_dict_temp['meetup']['categories'] = 'same'
                break
            elif categories.content.lower() == 'other':
                while True:
                    guild = Meowth.get_guild(guild.id)
                    guild_catlist = []
                    for cat in guild.categories:
                        guild_catlist.append(cat.id)
                    config_dict_temp['meetup']['categories'] = 'region'
                    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(),description=_("In the same order as they appear below, please give the names of the categories you would like raids reported in each channel to appear in. You do not need to use different categories for each channel, but they do need to be pre-existing categories. Separate each category name with a comma. Response can be either category name or ID.\n\nExample: `kansas city, hull, 1231231241561337813`\n\nYou have configured the following channels as meetup reporting channels.")).set_author(name=_('Meetup Reporting Categories'), icon_url=Meowth.user.avatar_url))
                    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_('{citychannel_list}').format(citychannel_list=citychannels.content.lower()[:2000])).set_author(name=_('Entered Channels'), icon_url=Meowth.user.avatar_url))
                    regioncats = await Meowth.wait_for('message', check=lambda message: message.guild == None and message.author == owner)
                    if regioncats.content.lower() == "cancel":
                        await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
                        return None
                    regioncat_list = regioncats.content.split(',')
                    regioncat_list = [x.strip() for x in regioncat_list]
                    regioncat_ids = []
                    regioncat_names = []
                    regioncat_errors = []
                    for item in regioncat_list:
                        category = None
                        if item.isdigit():
                            category = discord.utils.get(guild.categories, id=int(item))
                        if not category:
                            name = await letter_case(guild.categories, item.lower())
                            category = discord.utils.get(guild.categories, name=name)
                        if category:
                            regioncat_ids.append(category.id)
                            regioncat_names.append(category.name)
                        else:
                            regioncat_errors.append(item)
                    regioncat_list = regioncat_ids
                    if len(regioncat_list) == len(citychannel_list):
                        catdiff = set(regioncat_list) - set(guild_catlist)
                        if (not catdiff) and (not regioncat_errors):
                            for i in range(len(citychannel_list)):
                                category_dict[citychannel_list[i]] = regioncat_list[i]
                            break
                        else:
                            msg = _("The category list you provided doesn't match with your server's categories.")
                            if regioncat_errors:
                                msg += _("\n\nThe following aren't in your server: **{invalid_categories}**").format(invalid_categories=', '.join(regioncat_errors))
                            msg += _("\n\nPlease double check your category list and resend your response. If you just made these categories, try again.")
                            await owner.send(embed=discord.Embed(colour=discord.Colour.orange(),description=msg))
                            continue
                    else:
                        msg = _("The number of categories I found in your server doesn't match the number of channels you gave me earlier!\n\nI'll show you the two lists to compare:\n\n**Matched Channels:** {channellist}\n**Matched Categories:** {catlist}\n\nPlease double check that your categories match up with your provided channels and resend your response.").format(channellist=', '.join(citychannel_names), catlist=', '.join(regioncat_names) if len(regioncat_list)>0 else "None")
                        if regioncat_errors:
                            msg += _("\n\nThe following aren't in your server: **{invalid_categories}**").format(invalid_categories=', '.join(regioncat_errors))
                        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=msg))
                        continue
                    break
            else:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(),description=_("Sorry, I didn't understand your answer! Try again.")))
                continue
            break
        await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Meetup Categories are set')))
        config_dict_temp['meetup']['category_dict'] = category_dict
    ctx.config_dict_temp = config_dict_temp
    return ctx

@configure.command()
async def subscription(ctx):
    """!subscription settings"""
    return await _check_sessions_and_invoke(ctx, _configure_subscription)

async def _configure_subscription(ctx):
    guild = ctx.message.guild
    owner = ctx.message.author
    config_dict_temp = getattr(ctx, 'config_dict_temp',copy.deepcopy(guild_dict[guild.id]['configure_dict']))
    if 'subscriptions' not in config_dict_temp:
        config_dict_temp['subscriptions'] = {}
    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("The **!subscription** commmand lets users set up special triggers for me to send them a notification DM when an event they're interested in happens. I just need to know what channels you want to use to allow people to manage these notifications with the **!subscription** command.\n\nIf you don't want to allow the management of subscriptions, then you may want to disable this feature.\n\nRepond with: **N** to disable, or the **channel-name** list to enable, each seperated by a comma and space.")).set_author(name=_('Subscriptions'), icon_url=Meowth.user.avatar_url))
    while True:
        subchs = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
        if subchs.content.lower() == 'n':
            config_dict_temp['subscriptions']['enabled'] = False
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Subscriptions disabled')))
            break
        elif subchs.content.lower() == 'cancel':
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
            return None
        else:
            sub_list = subchs.content.lower().split(',')
            sub_list = [x.strip() for x in sub_list]
            guild_channel_list = []
            for channel in guild.text_channels:
                guild_channel_list.append(channel.id)
            sub_list_objs = []
            sub_list_names = []
            sub_list_errors = []
            for item in sub_list:
                channel = None
                if item.isdigit():
                    channel = discord.utils.get(guild.text_channels, id=int(item))
                if not channel:
                    item = re.sub(r'[^a-zA-Z0-9 _\-]+', '', item)
                    item = item.replace(" ","-")
                    name = await letter_case(guild.text_channels, item.lower())
                    channel = discord.utils.get(guild.text_channels, name=name)
                if channel:
                    sub_list_objs.append(channel)
                    sub_list_names.append(channel.name)
                else:
                    sub_list_errors.append(item)
            sub_list_set = [x.id for x in sub_list_objs]
            diff = set(sub_list_set) - set(guild_channel_list)
            if (not diff) and (not sub_list_errors):
                config_dict_temp['subscriptions']['enabled'] = True
                config_dict_temp['subscriptions']['report_channels'] = sub_list_set
                for channel in sub_list_objs:
                    ow = channel.overwrites_for(Meowth.user)
                    ow.send_messages = True
                    ow.read_messages = True
                    ow.manage_roles = True
                    try:
                        await channel.set_permissions(Meowth.user, overwrite = ow)
                    except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
                        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_('I couldn\'t set my own permissions in this channel. Please ensure I have the correct permissions in {channel} using **{prefix}get perms**.').format(prefix=ctx.prefix, channel=channel.mention)))
                await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Subscriptions enabled')))
                break
            else:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The channel list you provided doesn't match with your servers channels.\n\nThe following aren't in your server: **{invalid_channels}**\n\nPlease double check your channel list and resend your reponse.").format(invalid_channels=', '.join(sub_list_errors))))
                continue
    ctx.config_dict_temp = config_dict_temp
    return ctx

@configure.command()
async def archive(ctx):
    """Configure !archive command settings"""
    return await _check_sessions_and_invoke(ctx, _configure_archive)

async def _configure_archive(ctx):
    guild = ctx.message.guild
    owner = ctx.message.author
    config_dict_temp = getattr(ctx, 'config_dict_temp',copy.deepcopy(guild_dict[guild.id]['configure_dict']))
    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("The **!archive** command marks temporary raid channels for archival rather than deletion. This can be useful for investigating potential violations of your server's rules in these channels.\n\nIf you would like to disable this feature, reply with **N**. Otherwise send the category you would like me to place archived channels in. You can say **same** to keep them in the same category, or type the name or ID of a category in your server.")).set_author(name=_('Archive Configuration'), icon_url=Meowth.user.avatar_url))
    config_dict_temp['archive'] = {}
    while True:
        archivemsg = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
        if archivemsg.content.lower() == 'cancel':
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
            return None
        if archivemsg.content.lower() == 'same':
            config_dict_temp['archive']['category'] = 'same'
            config_dict_temp['archive']['enabled'] = True
            await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Archived channels will remain in the same category.')))
            break
        if archivemsg.content.lower() == 'n':
            config_dict_temp['archive']['enabled'] = False
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Archived Channels disabled.')))
            break
        else:
            item = archivemsg.content
            category = None
            if item.isdigit():
                category = discord.utils.get(guild.categories, id=int(item))
            if not category:
                name = await letter_case(guild.categories, item.lower())
                category = discord.utils.get(guild.categories, name=name)
            if not category:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("I couldn't find the category you replied with! Please reply with **same** to leave archived channels in the same category, or give the name or ID of an existing category.")))
                continue
            config_dict_temp['archive']['category'] = category.id
            config_dict_temp['archive']['enabled'] = True
            await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Archive category set.')))
            break
    if config_dict_temp['archive']['enabled']:
        await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("I can also listen in your raid channels for words or phrases that you want to trigger an automatic archival. For example, if discussion of spoofing is against your server rules, you might tell me to listen for the word 'spoofing'.\n\nReply with **none** to disable this feature, or reply with a comma separated list of phrases you want me to listen in raid channels for.")).set_author(name=_('Archive Configuration'), icon_url=Meowth.user.avatar_url))
        phrasemsg = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
        if phrasemsg.content.lower() == 'none':
            config_dict_temp['archive']['list'] = None
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Phrase list disabled.')))
        elif phrasemsg.content.lower() == 'cancel':
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
            return None
        else:
            phrase_list = phrasemsg.content.lower().split(",")
            for i in range(len(phrase_list)):
                phrase_list[i] = phrase_list[i].strip()
            config_dict_temp['archive']['list'] = phrase_list
            await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Archive Phrase list set.')))
    ctx.config_dict_temp = config_dict_temp
    return ctx

@configure.command(aliases=['settings'])
async def timezone(ctx):
    """Configure timezone and other settings"""
    return await _check_sessions_and_invoke(ctx, _configure_settings)

async def _configure_settings(ctx):
    guild = ctx.message.guild
    owner = ctx.message.author
    config_dict_temp = getattr(ctx, 'config_dict_temp',copy.deepcopy(guild_dict[guild.id]['configure_dict']))
    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("There are a few settings available that are not within **!configure**. To set these, use **!set <setting>** in any channel to set that setting.\n\nThese include:\n**!set regional <name or number>** - To set a server's regional raid boss\n**!set prefix <prefix>** - To set my command prefix\n**!set timezone <offset>** - To set offset outside of **!configure**\n**!set silph <trainer>** - To set a trainer's SilphRoad card (usable by members)\n**!set pokebattler <ID>** - To set a trainer's pokebattler ID (usable by members)\n\nHowever, we can do your timezone now to help coordinate reports for you. For others, use the **!set** command.\n\nThe current 24-hr time UTC is {utctime}. How many hours off from that are you?\n\nRespond with: A number from **-12** to **12**:").format(utctime=strftime('%H:%M', time.gmtime()))).set_author(name=_('Timezone Configuration and Other Settings'), icon_url=Meowth.user.avatar_url))
    while True:
        offsetmsg = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
        if offsetmsg.content.lower() == 'cancel':
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
            return None
        else:
            try:
                offset = float(offsetmsg.content)
            except ValueError:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("I couldn't convert your answer to an appropriate timezone!\n\nPlease double check what you sent me and resend a number strarting from **-12** to **12**.")))
                continue
            if (not ((- 12) <= offset <= 14)):
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("I couldn't convert your answer to an appropriate timezone!\n\nPlease double check what you sent me and resend a number strarting from **-12** to **12**.")))
                continue
            else:
                break
    config_dict_temp['settings']['offset'] = offset
    await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Timezone set')))
    ctx.config_dict_temp = config_dict_temp
    return ctx

@configure.command()
async def trade(ctx):
    """!trade reporting settings"""
    return await _check_sessions_and_invoke(ctx, _configure_trade)

async def _configure_trade(ctx):
    guild = ctx.message.guild
    owner = ctx.message.author
    config_dict_temp = getattr(ctx, 'config_dict_temp',copy.deepcopy(guild_dict[guild.id]['configure_dict']))
    await owner.send(embed=discord.Embed(colour=discord.Colour.lighter_grey(), description=_("The **!trade** command allows your users to organize and coordinate trades. This command requires at least one channel specifically for trades.\n\nIf you would like to disable this feature, reply with **N**. Otherwise, just send the names or IDs of the channels you want to allow the **!trade** command in, separated by commas.")).set_author(name=_('Trade Configuration'), icon_url=Meowth.user.avatar_url))
    while True:
        trademsg = await Meowth.wait_for('message', check=(lambda message: (message.guild == None) and message.author == owner))
        if trademsg.content.lower() == 'cancel':
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**CONFIG CANCELLED!**\n\nNo changes have been made.')))
            return None
        elif trademsg.content.lower() == 'n':
            config_dict_temp['trade'] = {'enabled': False, 'report_channels': []}
            await owner.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Trade disabled.')))
            break
        else:
            trade_list = trademsg.content.lower().split(',')
            trade_list = [x.strip() for x in trade_list]
            guild_channel_list = []
            for channel in guild.text_channels:
                guild_channel_list.append(channel.id)
            trade_list_objs = []
            trade_list_names = []
            trade_list_errors = []
            for item in trade_list:
                channel = None
                if item.isdigit():
                    channel = discord.utils.get(guild.text_channels, id=int(item))
                if not channel:
                    item = re.sub('[^a-zA-Z0-9 _\\-]+', '', item)
                    item = item.replace(" ","-")
                    name = await letter_case(guild.text_channels, item.lower())
                    channel = discord.utils.get(guild.text_channels, name=name)
                if channel:
                    trade_list_objs.append(channel)
                    trade_list_names.append(channel.name)
                else:
                    trade_list_errors.append(item)
            trade_list_set = [x.id for x in trade_list_objs]
            diff = set(trade_list_set) - set(guild_channel_list)
            if (not diff) and (not trade_list_errors):
                config_dict_temp['trade']['enabled'] = True
                config_dict_temp['trade']['report_channels'] = trade_list_set
                for channel in trade_list_objs:
                    ow = channel.overwrites_for(Meowth.user)
                    ow.send_messages = True
                    ow.read_messages = True
                    ow.manage_roles = True
                    try:
                        await channel.set_permissions(Meowth.user, overwrite = ow)
                    except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
                        await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_('I couldn\'t set my own permissions in this channel. Please ensure I have the correct permissions in {channel} using **{prefix}get perms**.').format(prefix=ctx.prefix, channel=channel.mention)))
                await owner.send(embed=discord.Embed(colour=discord.Colour.green(), description=_('Pokemon Trades enabled')))
                break
            else:
                await owner.send(embed=discord.Embed(colour=discord.Colour.orange(), description=_("The channel list you provided doesn't match with your servers channels.\n\nThe following aren't in your server: **{invalid_channels}**\n\nPlease double check your channel list and resend your reponse.").format(invalid_channels=', '.join(trade_list_errors))))
                continue
    ctx.config_dict_temp = config_dict_temp
    return ctx

@Meowth.command()
@checks.is_owner()
async def reload_json(ctx):
    """Reloads the JSON files for the server

    Usage: !reload_json
    Useful to avoid a full restart if boss list changed"""
    load_config()
    await ctx.message.add_reaction('☑')

@Meowth.command()
@checks.is_dev_or_owner()
async def raid_json(ctx, level=None, *, newlist=None):
    'Edits or displays raid_info.json\n\n    Usage: !raid_json [level] [list]'
    msg = ''
    if (not level) and (not newlist):
        for level in raid_info['raid_eggs']:
            msg += _('\n**Level {level} raid list:** `{raidlist}` \n').format(level=level, raidlist=raid_info['raid_eggs'][level]['pokemon'])
            for pkmn in raid_info['raid_eggs'][level]['pokemon']:
                p = Pokemon.get_pokemon(Meowth, pkmn)
                msg += '{name} ({number})'.format(name=str(p), number=p.id)
                msg += ' '
            msg += '\n'
        return await ctx.channel.send(msg)
    elif level in raid_info['raid_eggs'] and (not newlist):
        msg += _('**Level {level} raid list:** `{raidlist}` \n').format(level=level, raidlist=raid_info['raid_eggs'][level]['pokemon'])
        for pkmn in raid_info['raid_eggs'][level]['pokemon']:
            p = Pokemon.get_pokemon(Meowth, pkmn)
            msg += '{name} ({number})'.format(name=str(p), number=p.id)
            msg += ' '
        msg += '\n'
        return await ctx.channel.send(msg)
    elif level in raid_info['raid_eggs'] and newlist:
        newlist = [re.sub(r'\'', '', item).strip() for item in newlist.strip('[]').split(',')]
        try:
            monlist = [Pokemon.get_pokemon(Meowth, name).name.lower() for name in newlist]
        except:
            return await ctx.channel.send(_("I couldn't understand the list you supplied! Please use a comma-separated list of Pokemon species names."))
        msg += _('I will replace this:\n')
        msg += _('**Level {level} raid list:** `{raidlist}` \n').format(level=level, raidlist=raid_info['raid_eggs'][level]['pokemon'])
        for pkmn in raid_info['raid_eggs'][level]['pokemon']:
            p = Pokemon.get_pokemon(Meowth, pkmn)
            msg += '{name} ({number})'.format(name=p.name, number=p.id)
            msg += ' '
        msg += _('\n\nWith this:\n')
        msg += _('**Level {level} raid list:** `{raidlist}` \n').format(level=level, raidlist=monlist)
        for p in monlist:
            p = Pokemon.get_pokemon(Meowth, p)
            msg += '{name} ({number})'.format(name=p.name, number=p.id)
            msg += ' '
        msg += _('\n\nContinue?')
        question = await ctx.channel.send(msg)
        try:
            timeout = False
            res, reactuser = await ask(question, ctx.channel, ctx.author.id)
        except TypeError:
            timeout = True
        if timeout or res.emoji == '❎':
            return await ctx.channel.send(_("Configuration cancelled!"))
        elif res.emoji == '✅':
            with open(os.path.join('data', 'raid_info.json'), 'r') as fd:
                data = json.load(fd)
            data['raid_eggs'][level]['pokemon'] = monlist
            with open(os.path.join('data', 'raid_info.json'), 'w') as fd:
                json.dump(data, fd, indent=2, separators=(', ', ': '))
            load_config()
            await question.clear_reactions()
            await question.add_reaction('☑')
            return await ctx.channel.send(_("Configuration successful!"))
        else:
            return await ctx.channel.send(_("I'm not sure what went wrong, but configuration is cancelled!"))

@Meowth.command()
@commands.has_permissions(manage_guild=True)
async def reset_board(ctx, *, user=None, type=None):
    guild = ctx.guild
    trainers = guild_dict[guild.id]['trainers']
    tgt_string = ""
    tgt_trainer = None
    if user:
        converter = commands.MemberConverter()
        for argument in user.split():
            try:
                tgt_trainer = await converter.convert(ctx, argument)
                tgt_string = tgt_trainer.display_name
            except:
                tgt_trainer = None
                tgt_string = _("every user")
            if tgt_trainer:
                user = user.replace(argument,"").strip()
                break
        for argument in user.split():
            if "raid" in argument.lower():
                type = "raid_reports"
                break
            elif "egg" in argument.lower():
                type = "egg_reports"
                break
            elif "ex" in argument.lower():
                type = "ex_reports"
                break
            elif "wild" in argument.lower():
                type = "wild_reports"
                break
            elif "res" in argument.lower():
                type = "research_reports"
                break
    if not type:
        type = "total_reports"
    msg = _("Are you sure you want to reset the **{type}** report stats for **{target}**?").format(type=type, target=tgt_string)
    question = await ctx.channel.send(msg)
    try:
        timeout = False
        res, reactuser = await ask(question, ctx.message.channel, ctx.message.author.id)
    except TypeError:
        timeout = True
    await question.delete()
    if timeout or res.emoji == '❎':
        return
    elif res.emoji == '✅':
        pass
    else:
        return
    for trainer in trainers:
        if tgt_trainer:
            trainer = tgt_trainer.id
        if type == "total_reports":
            trainers[trainer]['raid_reports'] = 0
            trainers[trainer]['wild_reports'] = 0
            trainers[trainer]['ex_reports'] = 0
            trainers[trainer]['egg_reports'] = 0
            trainers[trainer]['research_reports'] = 0
            trainers[trainer]['joined'] = 0
        else:
            trainers[trainer][type] = 0
        if tgt_trainer:
            await ctx.send(_("{trainer}'s report stats have been cleared!").format(trainer=tgt_trainer.display_name))
            return
    await ctx.send("This server's report stats have been reset!")

@Meowth.command()
@commands.has_permissions(manage_channels=True)
@checks.raidchannel()
async def changeraid(ctx, newraid):
    """Changes raid boss.

    Usage: !changeraid <new pokemon or level>
    Only usable by admins."""
    message = ctx.message
    guild = message.guild
    channel = message.channel
    if (not channel) or (channel.id not in guild_dict[guild.id]['raidchannel_dict']):
        await channel.send(_('The channel you entered is not a raid channel.'))
        return
    if newraid.isdigit():
        raid_channel_name = _('{egg_level}-egg-').format(egg_level=newraid)
        raid_channel_name += sanitize_name(guild_dict[guild.id]['raidchannel_dict'][channel.id]['address'])
        guild_dict[guild.id]['raidchannel_dict'][channel.id]['egglevel'] = newraid
        guild_dict[guild.id]['raidchannel_dict'][channel.id]['pokemon'] = ''
        changefrom = guild_dict[guild.id]['raidchannel_dict'][channel.id]['type']
        guild_dict[guild.id]['raidchannel_dict'][channel.id]['type'] = 'egg'
        egg_img = raid_info['raid_eggs'][newraid]['egg_img']
        boss_list = []
        for entry in raid_info['raid_eggs'][newraid]['pokemon']:
            p = Pokemon.get_pokemon(Meowth, entry)
            boss_list.append((((str(p) + ' (') + str(p.id)) + ') ') + ''.join(p.types))
        raid_img_url = 'https://raw.githubusercontent.com/klords/Kyogre/master/images/eggs/{}?cache=0'.format(str(egg_img))
        raid_message = await channel.get_message(guild_dict[guild.id]['raidchannel_dict'][channel.id]['raidmessage'])
        report_channel = Meowth.get_channel(raid_message.raw_channel_mentions[0])
        report_message = await report_channel.get_message(guild_dict[guild.id]['raidchannel_dict'][channel.id]['raidreport'])
        oldembed = raid_message.embeds[0]
        raid_embed = discord.Embed(title=oldembed.title, url=oldembed.url, colour=message.guild.me.colour)
        if len(raid_info['raid_eggs'][newraid]['pokemon']) > 1:
            raid_embed.add_field(name=_('**Possible Bosses:**'), value=_('{bosslist1}').format(bosslist1='\n'.join(boss_list[::2])), inline=True)
            raid_embed.add_field(name='\u200b', value=_('{bosslist2}').format(bosslist2='\n'.join(boss_list[1::2])), inline=True)
        else:
            raid_embed.add_field(name=_('**Possible Bosses:**'), value=_('{bosslist}').format(bosslist=''.join(boss_list)), inline=True)
            raid_embed.add_field(name='\u200b', value='\u200b', inline=True)
        raid_embed.add_field(name=oldembed.fields[2].name, value=oldembed.fields[2].value, inline=True)
        raid_embed.add_field(name=oldembed.fields[3].name, value=oldembed.fields[3].value, inline=True)
        raid_embed.set_footer(text=oldembed.footer.text, icon_url=oldembed.footer.icon_url)
        raid_embed.set_thumbnail(url=raid_img_url)
        for field in oldembed.fields:
            t = _('team')
            s = _('status')
            if (t in field.name.lower()) or (s in field.name.lower()):
                raid_embed.add_field(name=field.name, value=field.value, inline=field.inline)
        if changefrom == "egg":
            raid_message.content = re.sub(_(r'level\s\d'), _('Level {}').format(newraid), raid_message.content, flags=re.IGNORECASE)
            report_message.content = re.sub(_(r'level\s\d'), _('Level {}').format(newraid), report_message.content, flags=re.IGNORECASE)
        else:
            raid_message.content = re.sub(_(r'.*\sraid\sreported'),_('Level {} reported').format(newraid), raid_message.content, flags=re.IGNORECASE)
            report_message.content = re.sub(_(r'.*\sraid\sreported'),_('Level {}').format(newraid), report_message.content, flags=re.IGNORECASE)
        await raid_message.edit(new_content=raid_message.content, embed=raid_embed, content=raid_message.content)
        try:
            await report_message.edit(new_content=report_message.content, embed=raid_embed, content=report_message.content)
        except (discord.errors.NotFound, AttributeError):
            pass
        await channel.edit(name=raid_channel_name, topic=channel.topic)
    elif newraid and not newraid.isdigit():
        # What a hack, subtract raidtime from exp time because _eggtoraid will add it back
        egglevel = guild_dict[guild.id]['raidchannel_dict'][channel.id]['egglevel']
        if egglevel == "0":
            egglevel = Pokemon.get_pokemon(Meowth, newraid).raid_level
        guild_dict[guild.id]['raidchannel_dict'][channel.id]['exp'] -= 60 * raid_info['raid_eggs'][egglevel]['raidtime']

        await _eggtoraid(newraid, channel, author=message.author)

@Meowth.command()
@commands.has_permissions(manage_channels=True)
@checks.raidchannel()
async def clearstatus(ctx):
    """Clears raid channel status lists.

    Usage: !clearstatus
    Only usable by admins."""
    msg = _("Are you sure you want to clear all status for this raid? Everybody will have to RSVP again. If you are wanting to clear one user's status, use `!setstatus <user> cancel`")
    question = await ctx.channel.send(msg)
    try:
        timeout = False
        res, reactuser = await ask(question, ctx.message.channel, ctx.message.author.id)
    except TypeError:
        timeout = True
    await question.delete()
    if timeout or res.emoji == '❎':
        return
    elif res.emoji == '✅':
        pass
    else:
        return
    try:
        guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['trainer_dict'] = {}
        await ctx.channel.send(_('Raid status lists have been cleared!'))
    except KeyError:
        pass

@Meowth.command()
@commands.has_permissions(manage_channels=True)
@checks.raidchannel()
async def setstatus(ctx, member: discord.Member, status,*, status_counts: str = ''):
    """Changes raid channel status lists.

    Usage: !setstatus <user> <status> [count]
    User can be a mention or ID number. Status can be maybeinterested/i, coming/c, here/h, or cancel/x
    Only usable by admins."""
    valid_status_list = ['interested', 'i', 'maybe', 'coming', 'c', 'here', 'h', 'cancel','x']
    if status not in valid_status_list:
        await ctx.message.channel.send(_("{status} is not a valid status!").format(status=status))
        return
    ctx.message.author = member
    ctx.message.content = "{}{} {}".format(ctx.prefix, status, status_counts)
    await ctx.bot.process_commands(ctx.message)

@Meowth.command()
@checks.allowarchive()
async def archive(ctx):
    """Marks a raid channel for archival.

    Usage: !archive"""
    message = ctx.message
    channel = message.channel
    await ctx.message.delete()
    await _archive(channel)

async def _archive(channel):
    guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['archive'] = True
    await asyncio.sleep(10)
    guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['archive'] = True

"""
Miscellaneous
"""

@Meowth.command(name='uptime')
async def cmd_uptime(ctx):
    "Shows Kyogre's uptime"
    guild = ctx.guild
    channel = ctx.channel
    embed_colour = guild.me.colour or discord.Colour.lighter_grey()
    uptime_str = await _uptime(Meowth)
    embed = discord.Embed(colour=embed_colour, icon_url=Meowth.user.avatar_url)
    embed.add_field(name=_('Uptime'), value=uptime_str)
    try:
        await channel.send(embed=embed)
    except discord.HTTPException:
        await channel.send(_('I need the `Embed links` permission to send this'))

async def _uptime(bot):
    'Shows info about Kyogre'
    time_start = bot.uptime
    time_now = datetime.datetime.now()
    ut = relativedelta(time_now, time_start)
    (ut.years, ut.months, ut.days, ut.hours, ut.minutes)
    if ut.years >= 1:
        uptime = _('{yr}y {mth}m {day}d {hr}:{min}').format(yr=ut.years, mth=ut.months, day=ut.days, hr=ut.hours, min=ut.minutes)
    elif ut.months >= 1:
        uptime = _('{mth}m {day}d {hr}:{min}').format(mth=ut.months, day=ut.days, hr=ut.hours, min=ut.minutes)
    elif ut.days >= 1:
        uptime = _('{day} days {hr} hrs {min} mins').format(day=ut.days, hr=ut.hours, min=ut.minutes)
    elif ut.hours >= 1:
        uptime = _('{hr} hrs {min} mins {sec} secs').format(hr=ut.hours, min=ut.minutes, sec=ut.seconds)
    else:
        uptime = _('{min} mins {sec} secs').format(min=ut.minutes, sec=ut.seconds)
    return uptime

@Meowth.command()
async def about(ctx):
    'Shows info about Kyogre'
    repo_url = 'https://github.com/klords/Kyogre'
    owner = Meowth.owner
    channel = ctx.channel
    uptime_str = await _uptime(Meowth)
    yourserver = ctx.message.guild.name
    yourmembers = len(ctx.message.guild.members)
    embed_colour = ctx.guild.me.colour or discord.Colour.lighter_grey()
    about = _("I'm Kyogre! A Pokemon Go helper bot for Discord!\n\nI'm a variant of the open-source Meowth bot made by FoglyOgly.\n\nFor questions or feedback regarding Kyogre, please contact us on [our GitHub repo]({repo_url})\n\n").format(repo_url=repo_url)
    member_count = 0
    guild_count = 0
    for guild in Meowth.guilds:
        guild_count += 1
        member_count += len(guild.members)
    embed = discord.Embed(colour=embed_colour, icon_url=Meowth.user.avatar_url)
    embed.add_field(name=_('About Kyogre'), value=about, inline=False)
    embed.add_field(name=_('Owner'), value=owner)
    if guild_count > 1:
        embed.add_field(name=_('Servers'), value=guild_count)
        embed.add_field(name=_('Members'), value=member_count)
    embed.add_field(name=_("Your Server"), value=yourserver)
    embed.add_field(name=_("Your Members"), value=yourmembers)
    embed.add_field(name=_('Uptime'), value=uptime_str)
    embed.set_footer(text=_('For support, contact us on our Discord server. Invite Code: hhVjAN8'))
    try:
        await channel.send(embed=embed)
    except discord.HTTPException:
        await channel.send(_('I need the `Embed links` permission to send this'))

@Meowth.command()
@checks.allowteam()
async def team(ctx,*,content):
    """Set your team role.

    Usage: !team <team name>
    The team roles have to be created manually beforehand by the server administrator."""
    guild = ctx.guild
    toprole = guild.me.top_role.name
    position = guild.me.top_role.position
    team_msg = _(' or ').join(['**!team {0}**'.format(team) for team in config['team_dict'].keys()])
    high_roles = []
    guild_roles = []
    lowercase_roles = []
    harmony = None
    for role in guild.roles:
        if (role.name.lower() in config['team_dict']) and (role.name not in guild_roles):
            guild_roles.append(role.name)
    lowercase_roles = [element.lower() for element in guild_roles]
    for team in config['team_dict'].keys():
        if team.lower() not in lowercase_roles:
            try:
                temp_role = await guild.create_role(name=team.lower(), hoist=False, mentionable=True)
                guild_roles.append(team.lower())
            except discord.errors.HTTPException:
                await message.channel.send(_('Maximum guild roles reached.'))
                return
            if temp_role.position > position:
                high_roles.append(temp_role.name)
    if high_roles:
        await ctx.channel.send(_('My roles are ranked lower than the following team roles: **{higher_roles_list}**\nPlease get an admin to move my roles above them!').format(higher_roles_list=', '.join(high_roles)))
        return
    role = None
    team_split = content.lower().split()
    entered_team = team_split[0]
    entered_team = ''.join([i for i in entered_team if i.isalpha()])
    if entered_team in lowercase_roles:
        index = lowercase_roles.index(entered_team)
        role = discord.utils.get(ctx.guild.roles, name=guild_roles[index])
    if 'harmony' in lowercase_roles:
        index = lowercase_roles.index('harmony')
        harmony = discord.utils.get(ctx.guild.roles, name=guild_roles[index])
    # Check if user already belongs to a team role by
    # getting the role objects of all teams in team_dict and
    # checking if the message author has any of them.    for team in guild_roles:
    for team in guild_roles:
        temp_role = discord.utils.get(ctx.guild.roles, name=team)
        if temp_role:
            # and the user has this role,
            if (temp_role in ctx.author.roles) and (harmony not in ctx.author.roles):
                # then report that a role is already assigned
                await ctx.channel.send(_('You already have a team role!'))
                return
            if role and (role.name.lower() == 'harmony') and (harmony in ctx.author.roles):
                # then report that a role is already assigned
                await ctx.channel.send(_('You are already in Team Harmony!'))
                return
        # If the role isn't valid, something is misconfigured, so fire a warning.
        else:
            await ctx.channel.send(_('{team_role} is not configured as a role on this server. Please contact an admin for assistance.').format(team_role=team))
            return
    # Check if team is one of the three defined in the team_dict
    if entered_team not in config['team_dict'].keys():
        await ctx.channel.send(_('"{entered_team}" isn\'t a valid team! Try {available_teams}').format(entered_team=entered_team, available_teams=team_msg))
        return
    # Check if the role is configured on the server
    elif role == None:
        await ctx.channel.send(_('The "{entered_team}" role isn\'t configured on this server! Contact an admin!').format(entered_team=entered_team))
    else:
        try:
            if harmony and (harmony in ctx.author.roles):
                await ctx.author.remove_roles(harmony)
            await ctx.author.add_roles(role)
            await ctx.channel.send(_('Added {member} to Team {team_name}! {team_emoji}').format(member=ctx.author.mention, team_name=role.name.capitalize(), team_emoji=parse_emoji(ctx.guild, config['team_dict'][entered_team])))
            await ctx.author.send(_("Now that you've set your team, head to <#449654496168247296> to set up your desired regions"))
        except discord.Forbidden:
            await ctx.channel.send(_("I can't add roles!"))

@Meowth.command(hidden=True)
async def profile(ctx, user: discord.Member = None):
    """Displays a user's social and reporting profile.

    Usage:!profile [user]"""
    if not user:
        user = ctx.message.author
    silph = guild_dict[ctx.guild.id]['trainers'].setdefault(user.id,{}).get('silphid',None)
    if silph:
        card = _("Traveler Card")
        silph = f"[{card}](https://sil.ph/{silph.lower()})"
    embed = discord.Embed(title=_("{user}\'s Trainer Profile").format(user=user.display_name), colour=user.colour)
    embed.set_thumbnail(url=user.avatar_url)
    embed.add_field(name=_("Silph Road"), value=f"{silph}", inline=True)
    embed.add_field(name=_("Pokebattler"), value=f"{guild_dict[ctx.guild.id]['trainers'].setdefault(user.id,{}).get('pokebattlerid',None)}", inline=True)
    embed.add_field(name=_("Raid Reports"), value=f"{guild_dict[ctx.guild.id]['trainers'].setdefault(user.id,{}).get('raid_reports',0)}", inline=True)
    embed.add_field(name=_("Egg Reports"), value=f"{guild_dict[ctx.guild.id]['trainers'].setdefault(user.id,{}).get('egg_reports',0)}", inline=True)
    embed.add_field(name=_("EX Raid Reports"), value=f"{guild_dict[ctx.guild.id]['trainers'].setdefault(user.id,{}).get('ex_reports',0)}", inline=True)
    embed.add_field(name=_("Wild Reports"), value=f"{guild_dict[ctx.guild.id]['trainers'].setdefault(user.id,{}).get('wild_reports',0)}", inline=True)
    embed.add_field(name=_("Research Reports"), value=f"{guild_dict[ctx.guild.id]['trainers'].setdefault(user.id,{}).get('research_reports',0)}", inline=True)
    await ctx.send(embed=embed)

@Meowth.command()
async def leaderboard(ctx, type="total"):
    """Displays the top ten reporters of a server.

    Usage: !leaderboard [type]
    Accepted types: raids, eggs, exraids, wilds, research"""
    trainers = copy.deepcopy(guild_dict[ctx.guild.id]['trainers'])
    leaderboard = []
    rank = 1
    field_value = ""
    typelist = ["total", "raids", "exraids", "wilds", "research", "eggs", "joined"]
    type = type.lower()
    if type not in typelist:
        await ctx.send(_("Leaderboard type not supported. Please select from: **total, raids, eggs, exraids, wilds, research**"))
        return
    for trainer in trainers.keys():
        user = ctx.guild.get_member(trainer)
        raids = trainers[trainer].setdefault('raid_reports', 0)
        wilds = trainers[trainer].setdefault('wild_reports', 0)
        exraids = trainers[trainer].setdefault('ex_reports', 0)
        eggs = trainers[trainer].setdefault('egg_reports', 0)
        research = trainers[trainer].setdefault('research_reports', 0)
        joined = trainers[trainer].setdefault('joined', 0)
        total_reports = raids + wilds + exraids + eggs + research + joined
        trainer_stats = {'trainer':trainer, 'total':total_reports, 'raids':raids, 'wilds':wilds, 'research':research, 'exraids':exraids, 'eggs':eggs, 'joined':joined}
        if trainer_stats[type] > 0 and user:
            leaderboard.append(trainer_stats)
    leaderboard = sorted(leaderboard,key= lambda x: x[type], reverse=True)[:10]
    embed = discord.Embed(colour=ctx.guild.me.colour)
    embed.set_author(name=_("Reporting Leaderboard ({type})").format(type=type.title()), icon_url=Meowth.user.avatar_url)
    for trainer in leaderboard:
        user = ctx.guild.get_member(trainer['trainer'])
        if user:
            if guild_dict[ctx.guild.id]['configure_dict']['raid']['enabled']:
                field_value += _("Raids: **{raids}** | Eggs: **{eggs}** | ").format(raids=trainer['raids'], eggs=trainer['eggs'])
            if guild_dict[ctx.guild.id]['configure_dict']['exraid']['enabled']:
                field_value += _("EX Raids: **{exraids}** | ").format(exraids=trainer['exraids'])
            if guild_dict[ctx.guild.id]['configure_dict']['wild']['enabled']:
                field_value += _("Wilds: **{wilds}** | ").format(wilds=trainer['wilds'])
            if guild_dict[ctx.guild.id]['configure_dict']['research']['enabled']:
                field_value += _("Research: **{research}** | ").format(research=trainer['research'])
            if guild_dict[ctx.guild.id]['configure_dict']['raid']['enabled']:
                field_value += _("Raids Joined: **{joined}** | ").format(joined=trainer['joined'])
            embed.add_field(name=f"{rank}. {user.display_name} - {type.title()}: **{trainer[type]}**", value=field_value[:-3], inline=False)
            field_value = ""
            rank += 1
    if len(embed.fields) == 0:
        embed.add_field(name=_("No Reports"), value=_("Nobody has made a report or this report type is disabled."))
    await ctx.send(embed=embed)

## TODO: UPDATE THIS:
"""
'configure_dict':{
            'welcome': {'enabled':False,'welcomechan':'','welcomemsg':''},
            'want': {'enabled':False, 'report_channels': []},
            'raid': {'enabled':False, 'report_channels': {}, 'categories':'same','category_dict':{}},
            'exraid': {'enabled':False, 'report_channels': {}, 'categories':'same','category_dict':{}, 'permissions':'everyone'},
            'counters': {'enabled':False, 'auto_levels': []},
            'wild': {'enabled':False, 'report_channels': {}},
            'research': {'enabled':False, 'report_channels': {}},
            'archive': {'enabled':False, 'category':'same','list':None},
            'invite': {'enabled':False},
            'team':{'enabled':False},
            'settings':{'offset':0,'regional':None,'done':False,'prefix':None,'config_sessions':{}}
        },
        'wildreport_dict:':{},
        'questreport_dict':{},
        'raidchannel_dict':{},
        'trainers':{}
"""
"""
Notifications
"""

def _get_subscription_command_error(content, subscription_types):
    error_message = None

    if ' ' not in content:
        return "Both a subscription type and target must be provided! Type `!help sub (add|remove|list)` for more details!"

    subscription, target = content.split(' ', 1)

    if subscription not in subscription_types:
        error_message = _("{subscription} is not a valid subscription type!".format(subscription=subscription.title()))

    if target == 'list':
        error_message = _("`list` is not a valid target. Did you mean `!sub list`?")
    
    return error_message

async def _parse_subscription_content(content, message = None):
    sub_list = []
    error_list = []
    raid_level_list = [str(n) for n in list(range(1, 6))]
    sub_type, target = content.split(' ', 1)

    if sub_type == 'gym':
        if message:
            channel = message.channel
            guild = message.guild
            trainer = message.author.id
            gyms = get_gyms(guild.id)
            if gyms:
                gym = await location_match_prompt(channel, trainer, target, gyms)
            if not gym:
                return await channel.send(_("No gym found with name '{0}'. Try again using the exact gym name!").format(target))
            sub_list.append((sub_type, gym.name, gym.name))
            return sub_list, error_list

    if sub_type == 'wild':
        perfect_pattern = r'((100(\s*%)?|perfect)(\s*ivs?\b)?)'
        target, count = re.subn(perfect_pattern, '', target, flags=re.I)
        if count:
            sub_list.append((sub_type, 'perfect', 'Perfect IVs'))
            
    if ',' in target:
        target = set([t.strip() for t in target.split(',')])
    else:
        target = set([target])

    if sub_type == 'raid':
        selected_levels = target.intersection(raid_level_list)
        for level in selected_levels:
            entry = f'L{level} Raids'
            target.remove(level)
            sub_list.append((sub_type, level, entry))
            
        ex_pattern = r'^(ex([- ]*eligible)?)$'
        ex_r = re.compile(ex_pattern, re.I)
        matches = list(filter(ex_r.match, target))
        if matches:
            entry = 'EX-Eligible Raids'
            for match in matches:
                target.remove(match)
            sub_list.append((sub_type, 'ex-eligible', entry))
    
    for name in target:
        pkmn = Pokemon.get_pokemon(Meowth, name)
        if pkmn:
            sub_list.append((sub_type, pkmn.name, pkmn.name))
        else:
            error_list.append(name)
    
    return sub_list, error_list

@Meowth.group(name="subscription", aliases=["sub"])
@checks.allowsubscription()
async def _sub(ctx):
    """Handles user subscriptions"""
    if ctx.invoked_subcommand == None:
        raise commands.BadArgument()

@_sub.command(name="add")
async def _sub_add(ctx, *, content):
    """Create a subscription

    Usage: !sub add <type> <target>
    Kyogre will send you a notification if an event is generated
    matching the details of your subscription.
    
    Valid types are: pokemon, raid, research, wild, and gym
    Note: 'Pokemon' includes raid, research, and wild reports"""
    subscription_types = ['pokemon','raid','research','wild','nest','gym']
    message = ctx.message
    channel = message.channel
    guild = message.guild
    trainer = message.author.id

    content = content.strip().lower()
    error_message = _get_subscription_command_error(content, subscription_types)
    if error_message:
        response = await message.channel.send(error_message)
        await asyncio.sleep(10)
        await message.delete()
        await response.delete()
        return

    error_list = []
    existing_list = []
    sub_list = []
    candidate_list, error_list = await _parse_subscription_content(content, message)
    guild_obj, __ = GuildTable.get_or_create(snowflake=guild.id)
    trainer_obj, __ = TrainerTable.get_or_create(snowflake=trainer, guild=guild.id)

    for sub in candidate_list:
        s_type = sub[0]
        s_target = sub[1]
        s_entry = sub[2]
        try:
            SubscriptionTable.create(trainer=trainer, type=s_type, target=s_target)
            sub_list.append(s_entry)
        except IntegrityError:
            existing_list.append(s_entry)
        except:
            error_list.append(s_entry)

    sub_count = len(sub_list)
    existing_count = len(existing_list)
    error_count = len(error_list)

    confirmation_msg = _('{member}, successfully added {count} new subscriptions').format(member=ctx.author.mention, count=sub_count)
    if sub_count > 0:
        confirmation_msg += _('\n**{sub_count} Added:** \n\t{sub_list}').format(sub_count=sub_count, sub_list=', '.join(sub_list))
    if existing_count > 0:
        confirmation_msg += _('\n**{existing_count} Already Existing:** \n\t{existing_list}').format(existing_count=existing_count, existing_list=', '.join(existing_list))
    if error_count > 0:
        confirmation_msg += _('\n**{error_count} Errors:** \n\t{error_list}\n(Check the spelling and try again)').format(error_count=error_count, error_list=', '.join(error_list))

    await channel.send(content=confirmation_msg)

@_sub.command(name="remove", aliases=["rm"])
async def _sub_remove(ctx,*,content):
    """Remove a subscription

    Usage: !sub remove <type> <target>
    You will no longer be notified of the specified target for the given event type.

    You can remove all subscriptions of a type:
    !sub remove <type> all

    Or remove all subscriptions:
    !sub remove all all"""
    subscription_types = ['all','pokemon','raid','research','wild','nest','gym']
    message = ctx.message
    channel = message.channel
    guild = message.guild
    trainer = message.author.id

    content = content.strip().lower()
    error_message = _get_subscription_command_error(content, subscription_types)
    if error_message:
        response = await message.channel.send(error_message)
        await asyncio.sleep(10)
        await message.delete()
        await response.delete()
        return

    candidate_list = []
    error_list = []
    not_found_list = []
    remove_list = []

    trainer_query = (TrainerTable
                        .select(TrainerTable.snowflake)
                        .where((TrainerTable.snowflake == trainer) & 
                        (TrainerTable.guild == guild.id)))

    # check for special cases
    skip_parse = False
    sub_type, target = content.split(' ', 1)
    if sub_type == 'all':
        if target == 'all':
            try:
                remove_count = SubscriptionTable.delete().where((SubscriptionTable.trainer << trainer_query)).execute()
                message = f'I removed your {remove_count} subscriptions!'
            except:
                message = 'I was unable to remove your subscriptions!'
            confirmation_msg = f'{message}'
            await channel.send(content=confirmation_msg)
            return
        else:
            target = target.split(',')
            if sub_type == 'pokemon':
                for name in target:
                    pkmn = Pokemon.get_pokemon(Meowth, name)
                    if pkmn:
                        candidate_list.append((sub_type, pkmn.name, pkmn.name))
                    else:
                        error_list.append(name)
            if sub_type != "gym":
                skip_parse = True
    elif target == 'all':
        candidate_list.append((sub_type, target, target))
        skip_parse = True
    if not skip_parse:
        candidate_list, error_list = await _parse_subscription_content(content, message)
    remove_count = 0
    for sub in candidate_list:
        s_type = sub[0]
        s_target = sub[1]
        s_entry = sub[2]
        try:
            if s_type == 'all':
                remove_count += SubscriptionTable.delete().where(
                    (SubscriptionTable.trainer << trainer_query) &
                    (SubscriptionTable.target == s_target)).execute()
            elif s_target == 'all':
                remove_count += SubscriptionTable.delete().where(
                    (SubscriptionTable.trainer << trainer_query) &
                    (SubscriptionTable.type == s_type)).execute()
            else:
                remove_count += SubscriptionTable.delete().where(
                    (SubscriptionTable.trainer << trainer_query) &
                    (SubscriptionTable.type == s_type) &
                    (SubscriptionTable.target == s_target)).execute()
            if remove_count > 0:
                remove_list.append(s_entry)
            else:
                not_found_list.append(s_entry)
        except:
            error_list.append(s_entry)

    not_found_count = len(not_found_list)
    error_count = len(error_list)

    confirmation_msg = _('{member}, successfully removed {count} subscriptions').format(member=ctx.author.mention, count=remove_count)
    if remove_count > 0:
        confirmation_msg += _('\n**{remove_count} Removed:** \n\t{remove_list}').format(remove_count=remove_count, remove_list=', '.join(remove_list))
    if not_found_count > 0:
        confirmation_msg += _('\n**{not_found_count} Not Found:** \n\t{not_found_list}').format(not_found_count=not_found_count, not_found_list=', '.join(not_found_list))
    if error_count > 0:
        confirmation_msg += _('\n**{error_count} Errors:** \n\t{error_list}\n(Check the spelling and try again)').format(error_count=error_count, error_list=', '.join(error_list))

    await channel.send(content=confirmation_msg)

@_sub.command(name="list", aliases=["ls"])
async def _sub_list(ctx, *, content=None):
    """List the subscriptions for the user

    Usage: !sub list <type> 
    Leave type empty to receive complete list of all subscriptions.
    Or include a type to receive a specific list
    Valid types are: pokemon, raid, research, wild, and gym"""
    message = ctx.message
    channel = message.channel
    author = message.author
    subscription_types = ['pokemon','raid','research','wild','nest', 'gym']
    response_msg = ''
    invalid_types = []
    valid_types = []
    results = (SubscriptionTable
                .select(SubscriptionTable.type, SubscriptionTable.target)
                .join(TrainerTable, on=(SubscriptionTable.trainer == TrainerTable.snowflake))
                .where(SubscriptionTable.trainer == ctx.author.id)
                .where(TrainerTable.guild == ctx.guild.id))

    if content:
        sub_types = [re.sub('[^A-Za-z]+', '', s.lower()) for s in content.split(',')]
        for s in sub_types:
            if s in subscription_types:
                valid_types.append(s)
            else:
                invalid_types.append(s)

        if (valid_types):
            results = results.where(SubscriptionTable.type << valid_types)
        else:
            response_msg = "No valid subscription types found! Valid types are: {types}".format(types=', '.join(subscription_types))
            response = await channel.send(response_msg)
            await asyncio.sleep(10)
            await response.delete()
            await message.delete()
            return
        
        if (invalid_types):
            response_msg = "\nUnable to find these subscription types: {inv}".format(inv=', '.join(invalid_types))
    
    results = results.execute()
        
    response_msg = f"{author.mention}, check your inbox! I've sent your subscriptions to you directly!" + response_msg  
    subscription_msg = ''
    types = set([s.type for s in results])
    subscriptions = {t: [s.target for s in results if s.type == t] for t in types}
    
    for sub in subscriptions:
        subscription_msg += '**{category}**:\n\t{subs}\n\n'.format(category=sub.title(),subs='\n\t'.join(subscriptions[sub]))
    if subscription_msg:
        if valid_types:
            listmsg = _('Your current {types} subscriptions are:\n\n{subscriptions}').format(types = ', '.join(valid_types), subscriptions=subscription_msg)
        else:
            listmsg = _('Your current subscriptions are:\n\n{subscriptions}').format(subscriptions=subscription_msg)
    else:
        if valid_types:
            listmsg = _("You don\'t have any subscriptions for {types}! use the **!subscription add** command to add some.").format(types = ', '.join(valid_types))
        else:
            listmsg = _("You don\'t have any subscriptions! use the **!subscription add** command to add some.")
    await author.send(listmsg)
    response = await channel.send(response_msg)
    await asyncio.sleep(10)
    await response.delete()
    await message.delete()

@_sub.command(name="adminlist", aliases=["alist"])
@commands.has_permissions(manage_guild=True)
async def _sub_adminlist(ctx, *, trainer=None):
    message = ctx.message
    channel = message.channel
    author = message.author
    response_msg = ''

    if not trainer:
        response_msg = "Please provide a trainer id"
        response = await channel.send(response_msg)
        await asyncio.sleep(10)
        await response.delete()
        await message.delete()
        return

    await message.add_reaction('✅')
    results = (SubscriptionTable
        .select(SubscriptionTable.type, SubscriptionTable.target)
        .join(TrainerTable, on=(SubscriptionTable.trainer == TrainerTable.snowflake))
        .where(SubscriptionTable.trainer == trainer)
        .where(TrainerTable.guild == ctx.guild.id))

    results = results.execute()
    subscription_msg = ''
    types = set([s.type for s in results])
    subscriptions = {t: [s.target for s in results if s.type == t] for t in types}

    for sub in subscriptions:
        subscription_msg += '**{category}**:\n\t{subs}\n\n'.format(category=sub.title(),subs='\n\t'.join(subscriptions[sub]))
    if subscription_msg:
        listmsg = _("Listing subscriptions for user with id {id}\n").format(id=trainer)
        listmsg += _('Current subscriptions are:\n\n{subscriptions}').format(subscriptions=subscription_msg)
    await author.send(listmsg)

"""
Reporting
"""
def get_existing_raid(guild, location, only_ex = False):
    """returns a list of channel ids for raids reported at the location provided"""
    report_dict = {k: v for k, v in guild_dict[guild.id]['raidchannel_dict'].items() if ((v.get('egglevel', '').lower() != 'ex') if not only_ex else (v.get('egglevel', '').lower() == 'ex'))}
    def matches_existing(report):
        # ignore meetups
        if report.get('meetup', {}):
            return False
        return report.get('gym', None) and report['gym'].name.lower() == location.name.lower()
    return [channel_id for channel_id, report in report_dict.items() if matches_existing(report)]

def get_existing_research(guild, location):
    """returns a list of confirmation message ids for research reported at the location provided"""
    report_dict = guild_dict[guild.id]['questreport_dict']
    def matches_existing(report):
        return report['location'].lower() == location.name.lower()
    return [confirmation_id for confirmation_id, report in report_dict.items() if matches_existing(report)]

@Meowth.command(name="wild", aliases=['w'])
@checks.allowwildreport()
async def _wild(ctx,pokemon,*,location):
    """Report a wild Pokemon spawn location.

    Usage: !wild <species> <location>
    Location should be the name of a Pokestop or Gym. Or a google maps link."""
    content = f"{pokemon} {location}"
    await _wild_internal(ctx.message, content)

async def _wild_internal(message, content):
    guild = message.guild
    channel = message.channel
    author = message.author
    timestamp = (message.created_at + datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])).strftime(_('%I:%M %p (%H:%M)'))
    if len(content.split()) <= 1:
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description='Give more details when reporting! Usage: **!wild <pokemon name> <location>**'))
    channel_regions = _get_channel_regions(channel, 'wild')
    rgx = r'\s*((100(\s*%)?|perfect)(\s*ivs?\b)?)\s*'
    content, count = re.subn(rgx, '', content.strip(), flags=re.I)
    is_perfect = count > 0
    entered_wild, wild_details = content.split(' ', 1)
    pkmn = Pokemon.get_pokemon(Meowth, entered_wild if entered_wild.isdigit() else content)
    if not pkmn:
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description="Unable to find that pokemon. Please check the name and try again!"))
    wild_number = pkmn.id
    wild_img_url = pkmn.img_url
    expiremsg = _('**This {pokemon} has despawned!**').format(pokemon=pkmn.full_name)
    wild_details = re.sub(pkmn.name.lower(), '', wild_details, flags=re.I)
    wild_gmaps_link = ''
    locations = get_all_locations(guild.id, channel_regions)
    if locations and not ('http' in wild_details or '/maps' in wild_details):
        location = await location_match_prompt(channel, author.id, wild_details, locations)
        if location:
            wild_gmaps_link = location.maps_url
            wild_details = location.name
    if not wild_gmaps_link:
        if 'http' in wild_details or '/maps' in wild_details:
            wild_gmaps_link = create_gmaps_query(wild_details, channel, type="wild")
            wild_details = 'Custom Map Pin'
        else:
            return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description="Please use the name of an existing pokestop or gym, or include a valid Google Maps link."))
    wild_embed = discord.Embed(title=_('Click here for my directions to the wild {pokemon}!').format(pokemon=pkmn.full_name), description=_("Ask {author} if my directions aren't perfect!").format(author=author.name), url=wild_gmaps_link, colour=guild.me.colour)
    wild_embed.add_field(name=_('**Details:**'), value=_('{emoji}{pokemon} ({pokemonnumber}) {type}').format(emoji='💯' if is_perfect else '',pokemon=pkmn.full_name, pokemonnumber=str(wild_number), type=''.join(types_to_str(guild, pkmn.types))), inline=False)
    wild_embed.set_thumbnail(url=wild_img_url)
    wild_embed.add_field(name=_('**Reactions:**'), value=_("{emoji}: I'm on my way!").format(emoji="🏎"))
    wild_embed.add_field(name='\u200b', value=_("{emoji}: The Pokemon despawned!").format(emoji="💨"))
    wild_embed.set_footer(text=_('Reported by {author} - {timestamp}').format(author=author.display_name, timestamp=timestamp), icon_url=author.avatar_url_as(format=None, static_format='jpg', size=32))
    wildreportmsg = await channel.send(content=_('Wild {pokemon} reported by {member}! Details: {location_details}').format(pokemon=pkmn.name, member=author.display_name, location_details=wild_details), embed=wild_embed)
    await asyncio.sleep(0.25)
    await wildreportmsg.add_reaction('🏎')
    await asyncio.sleep(0.25)
    await wildreportmsg.add_reaction('💨')
    await asyncio.sleep(0.25)
    wild_dict = copy.deepcopy(guild_dict[guild.id].get('wildreport_dict',{}))
    wild_dict[wildreportmsg.id] = {
        'exp':time.time() + 3600,
        'expedit': {"content":wildreportmsg.content,"embedcontent":expiremsg},
        'reportmessage':message.id,
        'reportchannel':channel.id,
        'reportauthor':author.id,
        'location':wild_details,
        'url':wild_gmaps_link,
        'pokemon':pkmn.name,
        'perfect':is_perfect,
        'omw': []
    }
    guild_dict[guild.id]['wildreport_dict'] = wild_dict
    wild_reports = guild_dict[guild.id].setdefault('trainers',{}).setdefault(author.id,{}).setdefault('wild_reports',0) + 1
    guild_dict[guild.id]['trainers'][author.id]['wild_reports'] = wild_reports
    wild_details = {'pokemon': pkmn, 'perfect': is_perfect, 'location': wild_details, 'regions': channel_regions}
    await _update_listing_channels(guild, 'wild', edit=False, regions=channel_regions)
    await _send_notifications_async('wild', wild_details, channel, [author.id])

@Meowth.command(name="raid", aliases=['r', 're', 'egg', 'regg', 'raidegg'])
@checks.allowraidreport()
async def _raid(ctx,pokemon,*,location:commands.clean_content(fix_channel_mentions=True)="", weather=None, timer=None):
    """Report an ongoing raid or a raid egg.

    Usage: !raid <species/level> <gym name> [minutes]
    Kyogre will attempt to find a gym with the name you provide
    Kyogre's message will also include the type weaknesses of the boss.

    Finally, Kyogre will create a separate channel for the raid report, for the purposes of organizing the raid."""
    content = f"{pokemon} {location}".lower()
    if pokemon.isdigit():
        new_channel = await _raidegg(ctx, content)
    else:
        new_channel = await _raid_internal(ctx, content)
    ctx.raid_channel = new_channel

async def _raid_internal(ctx, content):
    message = ctx.message
    channel = message.channel
    guild = channel.guild
    author = message.author
    fromegg = False
    eggtoraid = False
    if guild_dict[guild.id]['raidchannel_dict'].get(channel.id,{}).get('type') == "egg":
        fromegg = True
    timestamp = (message.created_at + datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])).strftime(_('%I:%M %p (%H:%M)'))
    raid_split = content.split()
    if len(raid_split) == 0:
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Give more details when reporting! Usage: **!raid <pokemon name> <location>**')))
    if raid_split[0] == 'egg':
        await _raidegg(ctx, content)
        return
    if fromegg == True:
        eggdetails = guild_dict[guild.id]['raidchannel_dict'][channel.id]
        egglevel = eggdetails['egglevel']
        if raid_split[0].lower() == 'assume':
            if config['allow_assume'][egglevel] == 'False':
                return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('**!raid assume** is not allowed for this level egg.')))
            if guild_dict[guild.id]['raidchannel_dict'][channel.id]['active'] == False:
                await _eggtoraid(raid_split[1].lower(), channel, author)
                return
            else:
                await _eggassume(" ".join(raid_split), channel, author)
                return
        elif (raid_split[0] == "alolan" and len(raid_split) > 2) or (raid_split[0] != "alolan" and len(raid_split) > 1):
            return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Please report new raids in a reporting channel.')))
        elif guild_dict[guild.id]['raidchannel_dict'][channel.id]['active'] == False:
            eggtoraid = True
        ## This is a hack but it allows users to report the just hatched boss before Kyogre catches up with hatching the egg.
        elif guild_dict[guild.id]['raidchannel_dict'][channel.id]['exp'] - 30 < datetime.datetime.now().timestamp():
            eggtoraid = True
        else:            
            return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Please wait until the egg has hatched before changing it to an open raid!')))
    raid_pokemon = Pokemon.get_pokemon(Meowth, content)
    pkmn_error = None
    pkmn_error_dict = {'not_pokemon': "I couldn't determine the Pokemon in your report.\nWhat raid boss or raid tier are you reporting?",
                       'not_boss': 'That Pokemon does not appear in raids!\nWhat is the correct Pokemon?',
                       'ex': ("The Pokemon {pokemon} only appears in EX Raids!\nWhat is the correct Pokemon?").format(pokemon=str(raid_pokemon).capitalize()),
                       'level': "That is not a valid raid tier. Please provide the raid boss or tier for your report."}
    if not raid_pokemon:
        pkmn_error = 'not_pokemon'
        try:
            new_content = content.split()
            pkmn_index = new_content.index('alolan')
            del new_content[pkmn_index + 1]
            del new_content[pkmn_index]
            new_content = ' '.join(new_content)
        except ValueError:
            new_content = ' '.join(content.split())
    elif not raid_pokemon.is_raid:
        pkmn_error = 'not_boss'
        try:
            new_content = content.split()
            pkmn_index = new_content.index('alolan')
            del new_content[pkmn_index + 1]
            del new_content[pkmn_index]
            new_content = ' '.join(new_content)
        except ValueError:
            new_content = content.split()
    elif raid_pokemon.is_exraid:
        pkmn_error = 'ex'
        new_content = ' '.join(content.split()[1:])
    if pkmn_error is not None:
        while True:
            pkmn_embed=discord.Embed(colour=discord.Colour.red(), description=pkmn_error_dict[pkmn_error])
            pkmn_embed.set_footer(text="Reply with 'cancel' to cancel your raid report.")
            pkmnquery_msg = await channel.send(embed=pkmn_embed)
            try:
                pokemon_msg = await Meowth.wait_for('message', timeout=30, check=(lambda reply: reply.author == author))
            except asyncio.TimeoutError:
                timeout_error_msg = await channel.send(embed=discord.Embed(colour=discord.Colour.light_grey(), description="You took too long to reply. Raid report cancelled."))
                await pkmnquery_msg.delete()
                return
            if pokemon_msg.clean_content == "cancel":
                await pkmnquery_msg.delete()
                await pokemon_msg.delete()
                cancelled_msg = await channel.send(embed=discord.Embed(colour=discord.Colour.light_grey(), description="Raid report cancelled."))
                return
            if pokemon_msg.clean_content.isdigit():
                if int(pokemon_msg.clean_content) > 0 and int(pokemon_msg.clean_content) <= 5:
                    return await _raidegg(ctx, ' '.join([str(pokemon_msg.clean_content), new_content]))
                else:
                    pkmn_error = 'level'
                    continue
            raid_pokemon = Pokemon.get_pokemon(Meowth, pokemon_msg.clean_content)
            if not raid_pokemon:
                pkmn_error = 'not_pokemon'
            elif not raid_pokemon.is_raid:
                pkmn_error = 'not_boss'
            elif raid_pokemon.is_exraid:
                pkmn_error = 'ex'
            else:
                await pkmnquery_msg.delete()
                await pokemon_msg.delete()
                break
            await pkmnquery_msg.delete()
            await pokemon_msg.delete()
            await asyncio.sleep(.5)
    else:
        new_content = ' '.join(content.split()[len(raid_pokemon.full_name.split()):])
    if fromegg:
        return await _eggtoraid(raid_pokemon.full_name, channel, author)
    if eggtoraid:
        return await _eggtoraid(new_content, channel, author)
    raid_split = new_content.strip().split()
    if len(raid_split) == 0:
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Give more details when reporting! Usage: **!raid <pokemon name> <location>**')))
    raidexp = False
    if raid_split[-1].isdigit() or ':' in raid_split[-1]:
        raidexp = await raid_time_check(channel, raid_split[-1])
        if raidexp is False:
            return
        else:
            del raid_split[-1]
            if _timercheck(raidexp, raid_info['raid_eggs'][raid_pokemon.raid_level]['raidtime']):
                time_embed = discord.Embed(description=_("That's too long. Level {raidlevel} Raid currently last no more than {hatchtime} minutes...\nExpire time will not be set.").format(raidlevel=raid_pokemon.raid_level, hatchtime=raid_info['raid_eggs'][raid_pokemon.raid_level]['hatchtime']), colour=discord.Colour.red())
                await channel.send(embed=time_embed)
                raidexp = False
    raid_details = ' '.join(raid_split)
    raid_details = raid_details.strip()
    if raid_details == '':
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Give more details when reporting! Usage: **!raid <pokemon name> <location>**')))
    weather_list = [_('none'), _('extreme'), _('clear'), _('sunny'), _('rainy'),
                    _('partlycloudy'), _('cloudy'), _('windy'), _('snow'), _('fog')]
    rgx = '[^a-zA-Z0-9]'
    weather = next((w for w in weather_list if re.sub(rgx, '', w) in re.sub(rgx, '', raid_details.lower())), None)
    if not weather:
        weather = guild_dict[guild.id]['raidchannel_dict'].get(channel.id,{}).get('weather', None)
    raid_pokemon.weather = weather
    raid_details = raid_details.replace(str(weather), '', 1)
    if raid_details == '':
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Give more details when reporting! Usage: **!raid <pokemon name> <location>**')))
    regions = _get_channel_regions(channel, 'raid')
    gym = None
    gyms = get_gyms(guild.id, regions)
    if gyms:
        gym = await location_match_prompt(channel, author.id, raid_details, gyms)
        if not gym:
            gym = await retry_gym_match(channel, author.id, raid_details, gyms)
            if gym is None:
                return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f"I couldn't find a gym named '{raid_details}'. Try again using the exact gym name!"))
        raid_channel_ids = get_existing_raid(guild, gym)
        if raid_channel_ids:
            raid_channel = Meowth.get_channel(raid_channel_ids[0])
            try:
                raid_dict_entry = guild_dict[guild.id]['raidchannel_dict'][raid_channel.id]
            except:
                return await message.add_reaction('\u274c')
            enabled = raid_channels_enabled(guild, channel)
            if raid_dict_entry and raid_dict_entry['active']:
                msg = f"A raid has already been reported for {gym.name}."
                if enabled:
                    msg += f" Coordinate in {raid_channel.mention}"
                return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=msg))
            else:
                await message.add_reaction('✅')
                location = raid_dict_entry.get('address', 'unknown gym')
                if not enabled:
                    await channel.send(f"The egg at {location} has hatched into a {raid_pokemon.name} raid!")
                return await _eggtoraid(raid_pokemon.name.lower(), raid_channel)

        raid_details = gym.name
        raid_gmaps_link = gym.maps_url
        regions = [gym.region]
    else:
        raid_gmaps_link = create_gmaps_query(raid_details, channel, type="raid")
    raid_channel = await create_raid_channel("raid", raid_pokemon, None, raid_details, channel)
    ow = raid_channel.overwrites_for(raid_channel.guild.default_role)
    ow.send_messages = True
    try:
        await raid_channel.set_permissions(raid_channel.guild.default_role, overwrite = ow)
    except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
        pass
    raid = discord.utils.get(guild.roles, name=raid_pokemon.species)
    raid_embed = discord.Embed(title=_('Click here for directions to the raid!'), url=raid_gmaps_link, colour=guild.me.colour)
    if gym:
        gym_info = _("**Name:** {0}\n**Notes:** {1}").format(raid_details, "_EX Eligible Gym_" if gym.ex_eligible else "N/A")
        raid_embed.add_field(name=_('**Gym:**'), value=gym_info, inline=False)
    raid_embed.add_field(name=_('**Details:**'), value=_('{pokemon} ({pokemonnumber}) {type}').format(pokemon=str(raid_pokemon), pokemonnumber=str(raid_pokemon.id), type=types_to_str(guild, raid_pokemon.types), inline=True))
    raid_embed.add_field(name=_('**Weaknesses:**'), value=_('{weakness_list}').format(weakness_list=types_to_str(guild, raid_pokemon.weak_against.keys()), inline=True))
    enabled = raid_channels_enabled(guild, channel)
    if enabled:
        raid_embed.add_field(name=_('**Next Group:**'), value=_('Set with **!starttime**'), inline=True)
        raid_embed.add_field(name=_('**Expires:**'), value=_('Set with **!timerset**'), inline=True)
    raid_embed.set_footer(text=_('Reported by {author} - {timestamp}').format(author=author.display_name, timestamp=timestamp), icon_url=author.avatar_url_as(format=None, static_format='jpg', size=32))
    raid_embed.set_thumbnail(url=raid_pokemon.img_url)
    report_embed = raid_embed
    msg = build_raid_report_message(gym, raid_pokemon.name, raidexp, enabled, raid_channel)
    raidreport = await channel.send(content=msg, embed=report_embed)
    await asyncio.sleep(1)
    raidmsg = _("{pokemon} raid reported by {member} in {citychannel} at {location_details} gym. Coordinate here!\n\nClick the question mark reaction to get help on the commands that work in here.\n\nThis channel will be deleted five minutes after the timer expires.").format(pokemon=str(raid_pokemon), member=author.display_name, citychannel=channel.mention, location_details=raid_details)
    raidmessage = await raid_channel.send(content=raidmsg, embed=raid_embed)
    await raidmessage.add_reaction('\u2754')
    await raidmessage.pin()
    level = raid_pokemon.raid_level
    if str(level) in guild_dict[guild.id]['configure_dict']['counters']['auto_levels']:
        try:
            ctrs_dict = await _get_generic_counters(guild, raid_pokemon, weather)
            ctrsmsg = "Here are the best counters for the raid boss in currently known weather conditions! Update weather with **!weather**. If you know the moveset of the boss, you can react to this message with the matching emoji and I will update the counters."
            ctrsmessage = await raid_channel.send(content=ctrsmsg,embed=ctrs_dict[0]['embed'])
            ctrsmessage_id = ctrsmessage.id
            await ctrsmessage.pin()
            for moveset in ctrs_dict:
                await ctrsmessage.add_reaction(ctrs_dict[moveset]['emoji'])
                await asyncio.sleep(0.25)
        except:
            ctrs_dict = {}
            ctrsmessage_id = None
    else:
        ctrs_dict = {}
        ctrsmessage_id = None
    guild_dict[guild.id]['raidchannel_dict'][raid_channel.id] = {
        'regions': regions,
        'reportcity': channel.id,
        'trainer_dict': {},
        'exp': time.time() + (60 * raid_info['raid_eggs'][str(level)]['raidtime']),
        'manual_timer': False,
        'active': True,
        'raidmessage': raidmessage.id,
        'raidreport': raidreport.id,
        'reportchannel': channel.id,
        'ctrsmessage': ctrsmessage_id,
        'address': raid_details,
        'type': 'raid',
        'pokemon': raid_pokemon.name.lower(),
        'egglevel': '0',
        'ctrs_dict': ctrs_dict,
        'moveset': 0,
        'weather': weather,
        'gym': gym,
        'reporter': author.id
    }
    if raidexp is not False:
        await _timerset(raid_channel, raidexp)
    else:
        await raid_channel.send(content=_('Hey {member}, if you can, set the time left on the raid using **!timerset <minutes>** so others can check it with **!timer**.').format(member=author.mention))
    event_loop.create_task(expiry_check(raid_channel))
    raid_reports = guild_dict[guild.id].setdefault('trainers',{}).setdefault(author.id,{}).setdefault('raid_reports',0) + 1
    guild_dict[guild.id]['trainers'][author.id]['raid_reports'] = raid_reports
    raid_details = {'pokemon': raid_pokemon, 'tier': raid_pokemon.raid_level, 'ex-eligible': gym.ex_eligible if gym else False, 'location': raid_details, 'regions': regions}
    await _update_listing_channels(guild, 'raid', edit=False, regions=regions)
    if enabled:
        await _send_notifications_async('raid', raid_details, raid_channel, [author.id])
    else:
        await _send_notifications_async('raid', raid_details, channel, [author.id])
    await raidreport.add_reaction('\u270f')
    await asyncio.sleep(0.25)
    await raidreport.add_reaction('🚫')
    await asyncio.sleep(0.25)
    return raid_channel

async def retry_gym_match(channel, author_id, raid_details, gyms):
    attempt = raid_details.split(' ')
    if len(attempt) > 1:
        if attempt[-2] == "alolan" and len(attempt) > 2:
            del attempt[-2]
        del attempt[-1]
    attempt = ' '.join(attempt)
    gym = await location_match_prompt(channel, author_id, attempt, gyms)
    if gym:
        return gym
    else:
        attempt = raid_details.split(' ')
        if len(attempt) > 1:
            if attempt[0] == "alolan" and len(attempt) > 2:
                del attempt[0]
            del attempt[0]
        attempt = ' '.join(attempt)
        gym = await location_match_prompt(channel, author_id, attempt, gyms)
        if gym:
            return gym
        else:
            return None

async def _raidegg(ctx, content):
    message = ctx.message
    channel = message.channel

    if checks.check_eggchannel(ctx) or checks.check_raidchannel(ctx):
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Please report new raids in a reporting channel.')))
    
    guild = message.guild
    author = message.author
    timestamp = (message.created_at + datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])).strftime(_('%I:%M %p (%H:%M)'))
    raidexp = False
    hourminute = False
    raidegg_split = content.split()
    if raidegg_split[0].lower() == 'egg':
        del raidegg_split[0]
    if len(raidegg_split) <= 1:
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Give more details when reporting! Usage: **!raidegg <level> <location>**')))
    if raidegg_split[0].isdigit():
        egg_level = int(raidegg_split[0])
        del raidegg_split[0]
    else:
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Give more details when reporting! Use at least: **!raidegg <level> <location>**. Type **!help** raidegg for more info.')))
    raidexp = False
    if raidegg_split[-1].isdigit() or ':' in raidegg_split[-1]:
        raidexp = await raid_time_check(channel, raidegg_split[-1])
        if raidexp is False:
            return
        else:
            del raidegg_split[-1]
            if _timercheck(raidexp, raid_info['raid_eggs'][str(egg_level)]['hatchtime']):
                time_embed = discord.Embed(description=_("That's too long. Level {raidlevel} Raid Eggs currently last no more than {hatchtime} minutes...\nHatch time will not be set.").format(raidlevel=egg_level, hatchtime=raid_info['raid_eggs'][str(egg_level)]['hatchtime']), colour=discord.Colour.red())
                await channel.send(embed=time_embed)
                raidexp = False
    raid_details = ' '.join(raidegg_split)
    raid_details = raid_details.strip()
    if raid_details == '':
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Give more details when reporting! Use at least: **!raidegg <level> <location>**. Type **!help** raidegg for more info.')))
    rgx = '[^a-zA-Z0-9]'
    weather_list = [_('none'), _('extreme'), _('clear'), _('sunny'), _('rainy'),
                    _('partlycloudy'), _('cloudy'), _('windy'), _('snow'), _('fog')]
    weather = next((w for w in weather_list if re.sub(rgx, '', w) in re.sub(rgx, '', raid_details.lower())), None)
    raid_details = raid_details.replace(str(weather), '', 1)
    if not weather:
        weather = guild_dict[guild.id]['raidchannel_dict'].get(channel.id,{}).get('weather', None)
    if raid_details == '':
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Give more details when reporting! Usage: **!raid <pokemon name> <location>**')))
    config_dict = guild_dict[guild.id]['configure_dict']
    regions = _get_channel_regions(channel, 'raid')
    gym = None
    gyms = get_gyms(guild.id, regions)
    if gyms:
        gym = await location_match_prompt(channel, author.id, raid_details, gyms)
        if not gym:
            gym = await retry_gym_match(channel, author.id, raid_details, gyms)
            if gym is None:
                return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=_("I couldn't find a gym named '{0}'. Try again using the exact gym name!").format(raid_details)))
        raid_channel_ids = get_existing_raid(guild, gym)
        if raid_channel_ids:
            raid_channel = Meowth.get_channel(raid_channel_ids[0])
            msg = f"A raid has already been reported for {gym.name}."
            enabled = raid_channels_enabled(guild, channel)
            if enabled:
                msg += f" Coordinate in {raid_channel.mention}"
            return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=msg))
        raid_details = gym.name
        raid_gmaps_link = gym.maps_url
        regions = [gym.region]
    else:
        raid_gmaps_link = create_gmaps_query(raid_details, channel, type="raid")
    if (egg_level > 5) or (egg_level == 0):
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=_('Raid egg levels are only from 1-5!')))
    else:
        egg_level = str(egg_level)
        egg_info = raid_info['raid_eggs'][egg_level]
        egg_img = egg_info['egg_img']
        boss_list = []
        for entry in egg_info['pokemon']:
            p = Pokemon.get_pokemon(Meowth, entry)
            boss_list.append(str(p) + ' (' + str(p.id) + ') ' + types_to_str(guild, p.types))
        raid_channel = await create_raid_channel("egg", None, egg_level, raid_details, channel)
        ow = raid_channel.overwrites_for(raid_channel.guild.default_role)
        ow.send_messages = True
        try:
            await raid_channel.set_permissions(raid_channel.guild.default_role, overwrite = ow)
        except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
            pass
        raid_img_url = 'https://raw.githubusercontent.com/klords/Kyogre/master/images/eggs/{}?cache=0'.format(str(egg_img))
        raid_embed = discord.Embed(title=_('Click here for directions to the coming raid!'), url=raid_gmaps_link, colour=message.guild.me.colour)
        if gym:
            gym_info = _("**Name:** {0}\n**Notes:** {1}").format(raid_details, "_EX Eligible Gym_" if gym.ex_eligible else "N/A")
            raid_embed.add_field(name=_('**Gym:**'), value=gym_info, inline=False)
        if len(egg_info['pokemon']) > 1:
            raid_embed.add_field(name=_('**Possible Bosses:**'), value=_('{bosslist1}').format(bosslist1='\n'.join(boss_list[::2])), inline=True)
            raid_embed.add_field(name='\u200b', value=_('{bosslist2}').format(bosslist2='\n'.join(boss_list[1::2])), inline=True)
        else:
            raid_embed.add_field(name=_('**Possible Bosses:**'), value=_('{bosslist}').format(bosslist=''.join(boss_list)), inline=True)
            raid_embed.add_field(name='\u200b', value='\u200b', inline=True)
        enabled = raid_channels_enabled(guild, channel)
        if enabled:
            raid_embed.add_field(name=_('**Next Group:**'), value=_('Set with **!starttime**'), inline=True)
            raid_embed.add_field(name=_('**Hatches:**'), value=_('Set with **!timerset**'), inline=True)
        raid_embed.set_footer(text=_('Reported by {author} - {timestamp}').format(author=author.display_name, timestamp=timestamp), icon_url=author.avatar_url_as(format=None, static_format='jpg', size=32))
        raid_embed.set_thumbnail(url=raid_img_url)
        msg = build_raid_report_message(gym, egg_level, raidexp, enabled, raid_channel)
        raidreport = await channel.send(content=msg, embed=raid_embed)
        await asyncio.sleep(1)
        raidmsg = _("Level {level} raid egg reported by {member} in {citychannel} at {location_details} gym. Coordinate here!\n\nClick the question mark reaction to get help on the commands that work in here.\n\nThis channel will be deleted five minutes after the timer expires.").format(level=egg_level, member=author.display_name, citychannel=channel.mention, location_details=raid_details)
        raidmessage = await raid_channel.send(content=raidmsg, embed=raid_embed)
        await raidmessage.add_reaction('\u2754')
        await raidmessage.pin()
        guild_dict[message.guild.id]['raidchannel_dict'][raid_channel.id] = {
            'regions': regions,
            'reportcity': channel.id,
            'trainer_dict': {},
            'exp': time.time() + (60 * raid_info['raid_eggs'][egg_level]['hatchtime']),
            'manual_timer': False,
            'active': True,
            'raidmessage': raidmessage.id,
            'raidreport': raidreport.id,
            'reportchannel': channel.id,
            'address': raid_details,
            'type': 'egg',
            'pokemon': '',
            'egglevel': egg_level,
            'moveset': 0,
            'weather': weather,
            'gym': gym,
            'reporter': author.id
        }
        if raidexp is not False:
            await _timerset(raid_channel, raidexp)
        else:
            await raid_channel.send(content=_('Hey {member}, if you can, set the time left until the egg hatches using **!timerset <minutes>** so others can check it with **!timer**.').format(member=author.mention))
        if len(raid_info['raid_eggs'][egg_level]['pokemon']) == 1:
            await _eggassume('assume ' + raid_info['raid_eggs'][egg_level]['pokemon'][0], raid_channel)
        elif egg_level == "5" and guild_dict[raid_channel.guild.id]['configure_dict']['settings'].get('regional',None) in raid_info['raid_eggs']["5"]['pokemon']:
            await _eggassume('assume ' + guild_dict[raid_channel.guild.id]['configure_dict']['settings']['regional'], raid_channel)
        event_loop.create_task(expiry_check(raid_channel))
        egg_reports = guild_dict[message.guild.id].setdefault('trainers',{}).setdefault(author.id,{}).setdefault('egg_reports',0) + 1
        guild_dict[message.guild.id]['trainers'][author.id]['egg_reports'] = egg_reports
        await _update_listing_channels(guild, 'raid', edit=False, regions=regions)
        raid_details = {'tier': egg_level, 'ex-eligible': gym.ex_eligible if gym else False, 'location': raid_details, 'regions': regions}
        if enabled:
            await _send_notifications_async('raid', raid_details, raid_channel, [author.id])
        else:
            await _send_notifications_async('raid', raid_details, channel, [author.id])
        await raidreport.add_reaction('\u270f')
        await asyncio.sleep(0.25)
        await raidreport.add_reaction('🚫')
        await asyncio.sleep(0.25)
        return raid_channel

def build_raid_report_message(gym, pokemon, raidexp, enabled, channel):
    guild = channel.guild
    if pokemon.isdigit():
        msg = _('T{level} egg @ {location}{ex}').format(ex=" (EX) " if gym.ex_eligible else "", level=pokemon, location=gym.name)
        type = "Hatches: "
    else:
        msg = _('{boss} @ {location}{ex}').format(ex=" (EX) " if gym.ex_eligible else "", boss=pokemon, location=gym.name)
        type = "Expires: "
    if raidexp is not False:
        now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])
        end = now + datetime.timedelta(minutes=raidexp)
        msg += _(' {type}{end}.').format(end=end.strftime(_('%I:%M %p')), type=type)
    if enabled:
        msg += _(" Coordinate in {channel}").format(channel=channel.mention)
    return msg

async def _eggassume(args, raid_channel, author=None):

    guild = raid_channel.guild
    eggdetails = guild_dict[guild.id]['raidchannel_dict'][raid_channel.id]
    report_channel = Meowth.get_channel(eggdetails['reportcity'])
    egglevel = eggdetails['egglevel']
    manual_timer = eggdetails['manual_timer']
    weather = eggdetails.get('weather', None)
    egg_report = await report_channel.get_message(eggdetails['raidreport'])
    raid_message = await raid_channel.get_message(eggdetails['raidmessage'])
    entered_raid = re.sub('[\\@]', '', args.lower().lstrip('assume').lstrip(' '))
    raid_pokemon = Pokemon.get_pokemon(Meowth, entered_raid)
    if not raid_pokemon:
        return
    if not raid_pokemon.is_raid:
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f'The Pokemon {raid_pokemon.name} does not appear in raids!'))
    elif raid_pokemon.name.lower() not in raid_info['raid_eggs'][egglevel]['pokemon']:
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f'The Pokemon {raid_pokemon.name} does not hatch from level {egglevel} raid eggs!'))
    guild_dict[guild.id]['raidchannel_dict'][raid_channel.id]['pokemon'] = raid_pokemon.name
    oldembed = raid_message.embeds[0]
    raid_gmaps_link = oldembed.url
    raidrole = discord.utils.get(guild.roles, name=raid_pokemon.species)
    raid_embed = discord.Embed(title=_('Click here for directions to the coming raid!'), url=raid_gmaps_link, colour=guild.me.colour)
    gym = eggdetails.get('gym', None)
    if gym:
        gym_info = _("**Name:** {0}\n**Notes:** {1}").format(gym.name, "_EX Eligible Gym_" if gym.ex_eligible else "N/A")
        raid_embed.add_field(name=_('**Gym:**'), value=gym_info, inline=False)
    raid_embed.add_field(name=_('**Details:**'), value=_('{pokemon} ({pokemonnumber}) {type}').format(pokemon=raid_pokemon.name, pokemonnumber=str(raid_pokemon.id), type=types_to_str(guild, raid_pokemon.types), inline=True))
    raid_embed.add_field(name=_('**Weaknesses:**'), value=_('{weakness_list}').format(weakness_list=types_to_str(guild, raid_pokemon.weak_against)), inline=True)
    for field in oldembed.fields:
        if "hatches" in field.name.lower():
            raid_embed.add_field(name=_('**Hatches:**'), value=field.value, inline=True)
        if "next group" in field.name.lower():
            raid_embed.add_field(name=_('**Next Group:**'), value=field.value, inline=True)
        if "team" in field.name.lower():
            raid_embed.add_field(name=field.name, value=field.value, inline=field.inline)
        if "status" in field.name.lower():
            raid_embed.add_field(name=field.name, value=field.value, inline=field.inline)
    raid_embed.set_footer(text=oldembed.footer.text, icon_url=oldembed.footer.icon_url)
    raid_embed.set_thumbnail(url=raid_pokemon.img_url)
    try:
        await raid_message.edit(new_content=raid_message.content, embed=raid_embed, content=raid_message.content)
        raid_message = raid_message.id
    except discord.errors.NotFound:
        raid_message = None
    try:
        await egg_report.edit(new_content=egg_report.content, embed=raid_embed, content=egg_report.content)
        egg_report = egg_report.id
    except discord.errors.NotFound:
        egg_report = None
    await raid_channel.send(_('This egg will be assumed to be {pokemon} when it hatches!').format(pokemon=raid_pokemon.full_name))
    if str(egglevel) in guild_dict[guild.id]['configure_dict']['counters']['auto_levels']:
        ctrs_dict = await _get_generic_counters(guild, raid_pokemon, weather)
        ctrsmsg = "Here are the best counters for the raid boss in currently known weather conditions! Update weather with **!weather**. If you know the moveset of the boss, you can react to this message with the matching emoji and I will update the counters."
        ctrsmessage = await raid_channel.send(content=ctrsmsg,embed=ctrs_dict[0]['embed'])
        ctrsmessage_id = ctrsmessage.id
        await ctrsmessage.pin()
        for moveset in ctrs_dict:
            await ctrsmessage.add_reaction(ctrs_dict[moveset]['emoji'])
            await asyncio.sleep(0.25)
    else:
        ctrs_dict = {}
        ctrsmessage_id = eggdetails.get('ctrsmessage', None)
    eggdetails['ctrs_dict'] = ctrs_dict
    eggdetails['ctrsmessage'] = ctrsmessage_id
    guild_dict[guild.id]['raidchannel_dict'][raid_channel.id] = eggdetails
    return

async def _eggtoraid(entered_raid, raid_channel, author=None):
    pkmn = Pokemon.get_pokemon(Meowth, entered_raid)
    if not pkmn:
        return
    eggdetails = guild_dict[raid_channel.guild.id]['raidchannel_dict'][raid_channel.id]
    egglevel = eggdetails['egglevel']
    if egglevel == "0":
        egglevel = pkmn.raid_level
    try:
        reportcitychannel = Meowth.get_channel(eggdetails['reportcity'])
        reportcity = reportcitychannel.name
    except (discord.errors.NotFound, AttributeError):
        reportcity = None
    manual_timer = eggdetails['manual_timer']
    trainer_dict = eggdetails['trainer_dict']
    egg_address = eggdetails['address']
    weather = eggdetails.get('weather', None)
    try:
        gym = eggdetails['gym']
    except:
        gym = None
    try:
        reporter = eggdetails['reporter']
    except:
        reporter = None
    try:
        reportchannel = eggdetails['reportchannel']
    except:
        reportchannel = None
    if reportchannel is not None:
        reportchannel = Meowth.get_channel(reportchannel)
    raid_message = await raid_channel.get_message(eggdetails['raidmessage'])
    if not reportcitychannel:
        async for message in raid_channel.history(limit=500, reverse=True):
            if message.author.id == raid_channel.guild.me.id:
                c = _('Coordinate here')
                if c in message.content:
                    reportcitychannel = message.raw_channel_mentions[0]
                    break
    if reportcitychannel:
        try:
            egg_report = await reportcitychannel.get_message(eggdetails['raidreport'])
        except (discord.errors.NotFound, discord.errors.HTTPException):
            egg_report = None
    starttime = eggdetails.get('starttime',None)
    duplicate = eggdetails.get('duplicate',0)
    archive = eggdetails.get('archive',False)
    meetup = eggdetails.get('meetup',{})
    raid_match = pkmn.is_raid
    if (not raid_match):
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f'The Pokemon {pkmn.name} does not appear in raids!'))
    if (egglevel.isdigit() and int(egglevel) > 0) or egglevel == 'EX':
        raidexp = eggdetails['exp'] + 60 * raid_info['raid_eggs'][str(egglevel)]['raidtime']
    else:
        raidexp = eggdetails['exp']
    end = datetime.datetime.utcfromtimestamp(raidexp) + datetime.timedelta(hours=guild_dict[raid_channel.guild.id]['configure_dict']['settings']['offset'])
    oldembed = raid_message.embeds[0]
    raid_gmaps_link = oldembed.url
    enabled = True
    if guild_dict[raid_channel.guild.id].get('raidchannel_dict',{}).get(raid_channel.id,{}).get('meetup',{}):
        guild_dict[raid_channel.guild.id]['raidchannel_dict'][raid_channel.id]['type'] = 'exraid'
        guild_dict[raid_channel.guild.id]['raidchannel_dict'][raid_channel.id]['egglevel'] = '0'
        await raid_channel.send(_("The event has started!"), embed=oldembed)
        await raid_channel.edit(topic="")
        event_loop.create_task(expiry_check(raid_channel))
        return
    if egglevel.isdigit():
        hatchtype = 'raid'
        raidreportcontent = _('The egg has hatched into a {pokemon} raid at {location_details} gym.').format(pokemon=entered_raid.capitalize(), location_details=egg_address)
        enabled = raid_channels_enabled(raid_channel.guild, raid_channel)
        if enabled:
            raidreportcontent += _('Coordinate in {raid_channel}').format(raid_channel=raid_channel.mention)
        raidmsg = _("The egg reported in {citychannel} hatched into a {pokemon} raid! Details: {location_details}. Coordinate here!\n\nClick the question mark reaction to get help on the commands that work in here.\n\nThis channel will be deleted five minutes after the timer expires.").format(citychannel=reportcitychannel.mention, pokemon=entered_raid.capitalize(), location_details=egg_address)
    elif egglevel == 'EX':
        hatchtype = 'exraid'
        if guild_dict[raid_channel.guild.id]['configure_dict']['invite']['enabled']:
            invitemsgstr = _("Use the **!invite** command to gain access and coordinate")
            invitemsgstr2 = _(" after using **!invite** to gain access")
        else:
            invitemsgstr = _("Coordinate")
            invitemsgstr2 = ""
        raidreportcontent = _('The EX egg has hatched into a {pokemon} raid! Details: {location_details}. {invitemsgstr} coordinate in {raid_channel}').format(pokemon=entered_raid.capitalize(), location_details=egg_address, invitemsgstr=invitemsgstr,raid_channel=raid_channel.mention)
        raidmsg = _("{pokemon} EX raid reported in {citychannel}! Details: {location_details}. Coordinate here{invitemsgstr2}!\n\nClick the question mark reaction to get help on the commands that work in here.\n\nThis channel will be deleted five minutes after the timer expires.").format(pokemon=entered_raid.capitalize(), citychannel=reportcitychannel.mention, location_details=egg_address, invitemsgstr2=invitemsgstr2)
    raid_channel_name = sanitize_name(pkmn.name.lower() + '_' + egg_address)
    raid = discord.utils.get(raid_channel.guild.roles, name=pkmn.species)
    raid_embed = discord.Embed(title=_('Click here for directions to the raid!'), url=raid_gmaps_link, colour=raid_channel.guild.me.colour)
    raid_embed.add_field(name=_('**Details:**'), value=_('{pokemon} ({pokemonnumber}) {type}').format(pokemon=pkmn.name, pokemonnumber=str(pkmn.id), type=types_to_str(raid_channel.guild, pkmn.types), inline=True))
    raid_embed.add_field(name=_('**Weaknesses:**'), value=_('{weakness_list}').format(weakness_list=types_to_str(raid_channel.guild, pkmn.weak_against)), inline=True)
    raid_embed.add_field(name=oldembed.fields[2].name, value=oldembed.fields[2].value, inline=True)
    if meetup:
        raid_embed.add_field(name=oldembed.fields[3].name, value=end.strftime(_('%B %d at %I:%M %p (%H:%M)')), inline=True)
    else:
        raid_embed.add_field(name=_('**Expires:**'), value=end.strftime(_('%B %d at %I:%M %p (%H:%M)')), inline=True)
    raid_embed.set_footer(text=oldembed.footer.text, icon_url=oldembed.footer.icon_url)
    raid_embed.set_thumbnail(url=pkmn.img_url)
    await raid_channel.edit(name=raid_channel_name, topic=end.strftime(_('Ends on %B %d at %I:%M %p (%H:%M)')))
    trainer_list = []
    trainer_dict = copy.deepcopy(guild_dict[raid_channel.guild.id]['raidchannel_dict'][raid_channel.id]['trainer_dict'])
    for trainer in trainer_dict.keys():
        try:
            user = raid_channel.guild.get_member(trainer)
        except (discord.errors.NotFound, AttributeError):
            continue
        if (trainer_dict[trainer].get('interest',None)) and (entered_raid not in trainer_dict[trainer]['interest']):
            guild_dict[raid_channel.guild.id]['raidchannel_dict'][raid_channel.id]['trainer_dict'][trainer]['status'] = {'maybe':0, 'coming':0, 'here':0, 'lobby':0}
            guild_dict[raid_channel.guild.id]['raidchannel_dict'][raid_channel.id]['trainer_dict'][trainer]['party'] = {'mystic':0, 'valor':0, 'instinct':0, 'unknown':0}
            guild_dict[raid_channel.guild.id]['raidchannel_dict'][raid_channel.id]['trainer_dict'][trainer]['count'] = 1
        else:
            guild_dict[raid_channel.guild.id]['raidchannel_dict'][raid_channel.id]['trainer_dict'][trainer]['interest'] = []
    await asyncio.sleep(1)
    trainer_dict = copy.deepcopy(guild_dict[raid_channel.guild.id]['raidchannel_dict'][raid_channel.id]['trainer_dict'])
    for trainer in trainer_dict.keys():
        if (trainer_dict[trainer]['status']['maybe']) or (trainer_dict[trainer]['status']['coming']) or (trainer_dict[trainer]['status']['here']):
            try:
                user = raid_channel.guild.get_member(trainer)
                trainer_list.append(user.mention)
            except (discord.errors.NotFound, AttributeError):
                continue
    trainers = ' ' + ', '.join(trainer_list) if trainer_list else ''
    await raid_channel.send(content=_("Trainers{trainer}: The raid egg has just hatched into a {pokemon} raid!\nIf you couldn't before, you're now able to update your status with **!coming** or **!here**. If you've changed your plans, use **!cancel**.").format(trainer=trainers, pokemon=entered_raid.title()), embed=raid_embed)
    raid_details = {'pokemon': pkmn, 'tier': pkmn.raid_level, 'ex-eligible': False if eggdetails['gym'] is None else eggdetails['gym'].ex_eligible, 'location': eggdetails['address'], 'regions': eggdetails['regions']}
    if enabled:
        await _send_notifications_async('raid', raid_details, raid_channel, [author] if author else [])
    else:
        await _send_notifications_async('raid', raid_details, reportchannel, [author] if author else [])
    for field in oldembed.fields:
        t = _('team')
        s = _('status')
        if (t in field.name.lower()) or (s in field.name.lower()):
            raid_embed.add_field(name=field.name, value=field.value, inline=field.inline)
    try:
        await raid_message.edit(new_content=raidmsg, embed=raid_embed, content=raidmsg)
        raid_message = raid_message.id
    except (discord.errors.NotFound, AttributeError):
        raid_message = None
    try:
        await egg_report.edit(new_content=raidreportcontent, embed=raid_embed, content=raidreportcontent)
        egg_report = egg_report.id
    except (discord.errors.NotFound, AttributeError):
        egg_report = None
    if str(egglevel) in guild_dict[raid_channel.guild.id]['configure_dict']['counters']['auto_levels'] and not eggdetails.get('pokemon', None):
        ctrs_dict = await _get_generic_counters(raid_channel.guild, pkmn, weather)
        ctrsmsg = "Here are the best counters for the raid boss in currently known weather conditions! Update weather with **!weather**. If you know the moveset of the boss, you can react to this message with the matching emoji and I will update the counters."
        ctrsmessage = await raid_channel.send(content=ctrsmsg,embed=ctrs_dict[0]['embed'])
        ctrsmessage_id = ctrsmessage.id
        await ctrsmessage.pin()
        for moveset in ctrs_dict:
            await ctrsmessage.add_reaction(ctrs_dict[moveset]['emoji'])
            await asyncio.sleep(0.25)
    else:
        ctrs_dict = eggdetails.get('ctrs_dict',{})
        ctrsmessage_id = eggdetails.get('ctrsmessage', None)
    regions = eggdetails.get('regions', None)
    guild_dict[raid_channel.guild.id]['raidchannel_dict'][raid_channel.id] = {
        'regions': regions,
        'reportcity': reportcitychannel.id,
        'trainer_dict': trainer_dict,
        'exp': raidexp,
        'manual_timer': manual_timer,
        'active': True,
        'raidmessage': raid_message,
        'raidreport': egg_report,
        'reportchannel': reportchannel.id,
        'address': egg_address,
        'type': hatchtype,
        'pokemon': pkmn.name.lower(),
        'egglevel': '0',
        'ctrs_dict': ctrs_dict,
        'ctrsmessage': ctrsmessage_id,
        'weather': weather,
        'moveset': 0,
        'gym': gym,
        'reporter': reporter
    }
    guild_dict[raid_channel.guild.id]['raidchannel_dict'][raid_channel.id]['starttime'] = starttime
    guild_dict[raid_channel.guild.id]['raidchannel_dict'][raid_channel.id]['duplicate'] = duplicate
    guild_dict[raid_channel.guild.id]['raidchannel_dict'][raid_channel.id]['archive'] = archive
    if author:
        raid_reports = guild_dict[raid_channel.guild.id].setdefault('trainers',{}).setdefault(author.id,{}).setdefault('raid_reports',0) + 1
        guild_dict[raid_channel.guild.id]['trainers'][author.id]['raid_reports'] = raid_reports
        await _edit_party(raid_channel, author)
    await _update_listing_channels(raid_channel.guild, 'raid', edit=False, regions=regions)
    event_loop.create_task(expiry_check(raid_channel))

@Meowth.command(aliases=['ex'])
@checks.allowexraidreport()
async def exraid(ctx, *,location:commands.clean_content(fix_channel_mentions=True)=""):
    """Report an upcoming EX raid.

    Usage: !exraid <location>
    Meowth will insert the details (really just everything after the species name) into a
    Google maps link and post the link to the same channel the report was made in.
    Meowth's message will also include the type weaknesses of the boss.

    Finally, Meowth will create a separate channel for the raid report, for the purposes of organizing the raid."""
    await _exraid(ctx, location)

async def _exraid(ctx, location):
    message = ctx.message
    channel = message.channel
    config_dict = guild_dict[message.guild.id]['configure_dict']
    timestamp = (message.created_at + datetime.timedelta(hours=config_dict['settings']['offset'])).strftime(_('%I:%M %p (%H:%M)'))
    if not location:
        await channel.send(_('Give more details when reporting! Usage: **!exraid <location>**'))
        return
    raid_details = location
    regions = _get_channel_regions(channel, 'raid')
    gym = None
    gyms = get_gyms(message.guild.id, regions)
    if gyms:
        gym = await location_match_prompt(message.channel, message.author.id, raid_details, gyms)
        if not gym:
            return await message.channel.send(_("I couldn't find a gym named '{0}'. Try again using the exact gym name!").format(raid_details))
        raid_channel_ids = get_existing_raid(message.guild, gym, only_ex=True)
        if raid_channel_ids:
            raid_channel = Meowth.get_channel(raid_channel_ids[0])
            return await message.channel.send(f"A raid has already been reported for {gym.name}. Coordinate in {raid_channel.mention}")
        raid_details = gym.name
        raid_gmaps_link = gym.maps_url
        regions = [gym.region]
    else:
        raid_gmaps_link = create_gmaps_query(raid_details, message.channel, type="exraid")
    egg_info = raid_info['raid_eggs']['EX']
    egg_img = egg_info['egg_img']
    boss_list = []
    for entry in egg_info['pokemon']:
        p = Pokemon.get_pokemon(Meowth, entry)
        boss_list.append(str(p) + ' (' + str(p.id) + ') ' + ''.join(p.types))
    raid_channel = await create_raid_channel("exraid", None, None, raid_details, message.channel)
    if config_dict['invite']['enabled']:
        for role in channel.guild.role_hierarchy:
            if role.permissions.manage_guild or role.permissions.manage_channels or role.permissions.manage_messages:
                try:
                    await raid_channel.set_permissions(role, send_messages=True)
                except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
                    pass
    raid_img_url = 'https://raw.githubusercontent.com/klords/Kyogre/master/images/eggs/{}?cache=0'.format(str(egg_img))
    raid_embed = discord.Embed(title=_('Click here for directions to the coming raid!'), url=raid_gmaps_link, colour=message.guild.me.colour)
    if len(egg_info['pokemon']) > 1:
        raid_embed.add_field(name=_('**Possible Bosses:**'), value=_('{bosslist1}').format(bosslist1='\n'.join(boss_list[::2])), inline=True)
        raid_embed.add_field(name='\u200b', value=_('{bosslist2}').format(bosslist2='\n'.join(boss_list[1::2])), inline=True)
    else:
        raid_embed.add_field(name=_('**Possible Bosses:**'), value=_('{bosslist}').format(bosslist=''.join(boss_list)), inline=True)
        raid_embed.add_field(name='\u200b', value='\u200b', inline=True)
    raid_embed.add_field(name=_('**Next Group:**'), value=_('Set with **!starttime**'), inline=True)
    raid_embed.add_field(name=_('**Expires:**'), value=_('Set with **!timerset**'), inline=True)
    raid_embed.set_footer(text=_('Reported by {author} - {timestamp}').format(author=message.author, timestamp=timestamp), icon_url=message.author.avatar_url_as(format=None, static_format='jpg', size=32))
    raid_embed.set_thumbnail(url=raid_img_url)
    if config_dict['invite']['enabled']:
        invitemsgstr = _("Use the **!invite** command to gain access and coordinate")
        invitemsgstr2 = _(" after using **!invite** to gain access")
    else:
        invitemsgstr = _("Coordinate")
        invitemsgstr2 = ""
    raidreport = await channel.send(content=_('EX raid egg reported by {member}! Details: {location_details}. {invitemsgstr} in {raid_channel}').format(member=message.author.mention, location_details=raid_details, invitemsgstr=invitemsgstr,raid_channel=raid_channel.mention), embed=raid_embed)
    await asyncio.sleep(1)
    raidmsg = _("EX raid reported by {member} in {citychannel}! Details: {location_details}. Coordinate here{invitemsgstr2}!\n\nClick the question mark reaction to get help on the commands that work in here.\n\nThis channel will be deleted five minutes after the timer expires.").format(member=message.author.display_name, citychannel=message.channel.mention, location_details=raid_details, invitemsgstr2=invitemsgstr2)
    raidmessage = await raid_channel.send(content=raidmsg, embed=raid_embed)
    await raidmessage.add_reaction('\u2754')
    await raidmessage.pin()
    guild_dict[message.guild.id]['raidchannel_dict'][raid_channel.id] = {
        'regions': regions,
        'reportcity': channel.id,
        'trainer_dict': {},
        'exp': time.time() + (((60 * 60) * 24) * raid_info['raid_eggs']['EX']['hatchtime']),
        'manual_timer': False,
        'active': True,
        'raidmessage': raidmessage.id,
        'raidreport': raidreport.id,
        'address': raid_details,
        'type': 'egg',
        'pokemon': '',
        'egglevel': 'EX',
        'gym': gym,
        'reporter': message.author.id
    }
    if len(raid_info['raid_eggs']['EX']['pokemon']) == 1:
        await _eggassume('assume ' + raid_info['raid_eggs']['EX']['pokemon'][0], raid_channel)
    await raid_channel.send(content=_('Hey {member}, if you can, set the time left until the egg hatches using **!timerset <date and time>** so others can check it with **!timer**. **<date and time>** can just be written exactly how it appears on your EX Raid Pass.').format(member=message.author.mention))
    ex_reports = guild_dict[message.guild.id].setdefault('trainers',{}).setdefault(message.author.id,{}).setdefault('ex_reports',0) + 1
    guild_dict[message.guild.id]['trainers'][message.author.id]['ex_reports'] = ex_reports
    event_loop.create_task(expiry_check(raid_channel))

@Meowth.command()
@checks.allowinvite()
async def invite(ctx):
    """Join an EX Raid.

    Usage: !invite"""
    await _invite(ctx)

async def _invite(ctx):
    bot = ctx.bot
    channel = ctx.channel
    author = ctx.author
    guild = ctx.guild
    await channel.trigger_typing()
    exraidlist = ''
    exraid_dict = {}
    exraidcount = 0
    rc_dict = bot.guild_dict[guild.id]['raidchannel_dict']
    for channelid in rc_dict:
        if (not discord.utils.get(guild.text_channels, id=channelid)) or rc_dict[channelid].get('meetup',{}):
            continue
        if (rc_dict[channelid]['egglevel'] == 'EX') or (rc_dict[channelid]['type'] == 'exraid'):
            if guild_dict[guild.id]['configure_dict']['exraid']['permissions'] == "everyone" or (guild_dict[guild.id]['configure_dict']['exraid']['permissions'] == "same" and rc_dict[channelid]['reportcity'] == channel.id):
                exraid_channel = bot.get_channel(channelid)
                if exraid_channel.mention != '#deleted-channel':
                    exraidcount += 1
                    exraidlist += (('\n**' + str(exraidcount)) + '.**   ') + exraid_channel.mention
                    exraid_dict[str(exraidcount)] = exraid_channel
    if exraidcount == 0:
        await channel.send(_('No EX Raids have been reported in this server! Use **!exraid** to report one!'))
        return
    exraidchoice = await channel.send(_("{0}, you've told me you have an invite to an EX Raid, and I'm just going to take your word for it! The following {1} EX Raids have been reported:\n{2}\nReply with **the number** (1, 2, etc) of the EX Raid you have been invited to. If none of them match your invite, type 'N' and report it with **!exraid**").format(author.mention, str(exraidcount), exraidlist))
    reply = await bot.wait_for('message', check=(lambda message: (message.author == author)))
    if reply.content.lower() == 'n':
        await exraidchoice.delete()
        exraidmsg = await channel.send(_('Be sure to report your EX Raid with **!exraid**!'))
    elif (not reply.content.isdigit()) or (int(reply.content) > exraidcount):
        await exraidchoice.delete()
        exraidmsg = await channel.send(_("I couldn't tell which EX Raid you meant! Try the **!invite** command again, and make sure you respond with the number of the channel that matches!"))
    elif (int(reply.content) <= exraidcount) and (int(reply.content) > 0):
        await exraidchoice.delete()
        overwrite = discord.PermissionOverwrite()
        overwrite.send_messages = True
        overwrite.read_messages = True
        exraid_channel = exraid_dict[str(int(reply.content))]
        try:
            await exraid_channel.set_permissions(author, overwrite=overwrite)
        except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
            pass
        exraidmsg = await channel.send(_('Alright {0}, you can now send messages in {1}! Make sure you let the trainers in there know if you can make it to the EX Raid!').format(author.mention, exraid_channel.mention))
        await _maybe(exraid_channel, author, 1, party=None)
    else:
        await exraidchoice.delete()
        exraidmsg = await channel.send(_("I couldn't understand your reply! Try the **!invite** command again!"))
    await asyncio.sleep(30)
    await ctx.message.delete()
    await reply.delete()
    await exraidmsg.delete()

@Meowth.command(aliases=['res'])
@checks.allowresearchreport()
async def research(ctx, *, details = None):
    """Report Field research
    Start a guided report method with just !research. 

    If you want to do a quick report, provide the pokestop name followed by the task text with a comma in between.
    Do not include any other commas.

    If you reverse the order, Kyogre will attempt to determine the pokestop.

    Usage: !research [pokestop name, quest]"""
    message = ctx.message
    channel = message.channel
    author = message.author
    guild = message.guild
    timestamp = (message.created_at + datetime.timedelta(hours=guild_dict[message.channel.guild.id]['configure_dict']['settings']['offset']))
    to_midnight = 24*60*60 - ((timestamp-timestamp.replace(hour=0, minute=0, second=0, microsecond=0)).seconds)
    error = False
    loc_url = create_gmaps_query("", message.channel, type="research")
    research_embed = discord.Embed(colour=message.guild.me.colour).set_thumbnail(url='https://raw.githubusercontent.com/klords/Kyogre/master/images/misc/field-research.png?cache=0')
    research_embed.set_footer(text=_('Reported by {author} - {timestamp}').format(author=author.display_name, timestamp=timestamp.strftime(_('%I:%M %p (%H:%M)'))), icon_url=author.avatar_url_as(format=None, static_format='jpg', size=32))
    config_dict = guild_dict[guild.id]['configure_dict']
    regions = _get_channel_regions(channel, 'research')
    stops = None
    stops = get_stops(guild.id, regions)
    while True:
        if details:
            research_split = details.rsplit(",", 1)
            if len(research_split) != 2:
                error = _("entered an incorrect amount of arguments.\n\nUsage: **!research** or **!research <pokestop>, <quest>**")
                break
            location, quest_name = research_split
            if stops:
                stop = await location_match_prompt(channel, author.id, location, stops)
                if not stop:
                    quest_name, location = research_split
                    stop = await location_match_prompt(channel, author.id, location, stops)
                    if not stop:
                        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f"I couldn't find a pokestop named '{location}'. Try again using the exact pokestop name!"))
                if get_existing_research(guild, stop):
                    return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f"A quest has already been reported for {stop.name}"))
                location = stop.name
                loc_url = stop.maps_url
                regions = [stop.region]
            else:
                loc_url = create_gmaps_query(location, channel, type="research")
            location = location.replace(loc_url,"").strip()
            quest = await _get_quest(ctx, quest_name)
            if not quest:
                return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f"I couldn't find a quest named '{quest_name}'"))
            reward = await _prompt_reward(ctx, quest)
            if not reward:
                return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f"I couldn't find a reward for '{quest_name}'"))
            research_embed.add_field(name=_("**Pokestop:**"),value='\n'.join(textwrap.wrap(location.title(), width=30)),inline=True)
            research_embed.add_field(name=_("**Quest:**"),value='\n'.join(textwrap.wrap(quest.name.title(), width=30)),inline=True)
            research_embed.add_field(name=_("**Reward:**"),value='\n'.join(textwrap.wrap(reward.title(), width=30)),inline=True)
            break
        else:
            research_embed.add_field(name=_('**New Research Report**'), value=_("I'll help you report a research quest!\n\nFirst, I'll need to know what **pokestop** you received the quest from. Reply with the name of the **pokestop**. You can reply with **cancel** to stop anytime."), inline=False)
            pokestopwait = await channel.send(embed=research_embed)
            try:
                pokestopmsg = await Meowth.wait_for('message', timeout=60, check=(lambda reply: reply.author == message.author))
            except asyncio.TimeoutError:
                pokestopmsg = None
            await pokestopwait.delete()
            if not pokestopmsg:
                error = _("took too long to respond")
                break
            elif pokestopmsg.clean_content.lower() == "cancel":
                error = _("cancelled the report")
                await pokestopmsg.delete()
                break
            elif pokestopmsg:
                location = pokestopmsg.clean_content
                if stops:
                    stop = await location_match_prompt(channel, author.id, location, stops)
                    if not stop:
                        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f"I couldn't find a pokestop named '{location}'. Try again using the exact pokestop name!"))
                    if get_existing_research(guild, stop):
                        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f"A quest has already been reported for {stop.name}"))
                    location = stop.name
                    loc_url = stop.maps_url
                    regions = [stop.region]
                else:
                    loc_url = create_gmaps_query(location, channel, type="research")
                location = location.replace(loc_url,"").strip()
            await pokestopmsg.delete()
            research_embed.add_field(name=_("**Pokestop:**"),value='\n'.join(textwrap.wrap(location.title(), width=30)),inline=True)
            research_embed.set_field_at(0, name=research_embed.fields[0].name, value=_("Great! Now, reply with the **quest** that you received from **{location}**. You can reply with **cancel** to stop anytime.\n\nHere's what I have so far:").format(location=location), inline=False)
            questwait = await channel.send(embed=research_embed)
            try:
                questmsg = await Meowth.wait_for('message', timeout=60, check=(lambda reply: reply.author == message.author))
            except asyncio.TimeoutError:
                questmsg = None
            await questwait.delete()
            if not questmsg:
                error = _("took too long to respond")
                break
            elif questmsg.clean_content.lower() == "cancel":
                error = _("cancelled the report")
                await questmsg.delete()
                break
            elif questmsg:
                quest = await _get_quest(ctx, questmsg.clean_content)
            await questmsg.delete()
            if not quest:
                error = "didn't identify the quest"
                break
            research_embed.add_field(name=_("**Quest:**"),value='\n'.join(textwrap.wrap(quest.name.title(), width=30)),inline=True)
            reward = await _prompt_reward(ctx, quest)
            if not reward:
                error = "didn't identify the reward"
                break
            research_embed.add_field(name=_("**Reward:**"),value='\n'.join(textwrap.wrap(reward.title(), width=30)),inline=True)
            research_embed.remove_field(0)
            break
    if not error:
        research_msg = _("Field Research reported by {author}").format(author=author.display_name)
        research_embed.title = _('Click here for my directions to the research!')
        research_embed.description = _("Ask {author} if my directions aren't perfect!").format(author=author.name)
        research_embed.url = loc_url
        confirmation = await channel.send(research_msg,embed=research_embed)
        await asyncio.sleep(0.25)
        await confirmation.add_reaction('\u270f')
        await asyncio.sleep(0.25)
        await confirmation.add_reaction('🚫')
        await asyncio.sleep(0.25)
        research_dict = copy.deepcopy(guild_dict[guild.id].get('questreport_dict',{}))
        research_dict[confirmation.id] = {
            'regions': regions,
            'exp':time.time() + to_midnight,
            'expedit':"delete",
            'reportmessage':message.id,
            'reportchannel':channel.id,
            'reportauthor':author.id,
            'location':location,
            'url':loc_url,
            'quest':quest.name,
            'reward':reward
        }
        guild_dict[guild.id]['questreport_dict'] = research_dict
        research_reports = guild_dict[ctx.guild.id].setdefault('trainers',{}).setdefault(author.id,{}).setdefault('research_reports',0) + 1
        guild_dict[ctx.guild.id]['trainers'][author.id]['research_reports'] = research_reports
        await _update_listing_channels(guild, 'research', edit=False, regions=regions)
        if 'encounter' in reward.lower():
            pokemon = reward.rsplit(maxsplit=1)[0]
            research_details = {'pokemon': [Pokemon.get_pokemon(Meowth, p) for p in re.split(r'\s*,\s*', pokemon)], 'location': location, 'regions': regions}
            await _send_notifications_async('research', research_details, channel, [message.author.id])
    else:
        research_embed.clear_fields()
        research_embed.add_field(name=_('**Research Report Cancelled**'), value=_("Your report has been cancelled because you {error}! Retry when you're ready.").format(error=error), inline=False)
        confirmation = await channel.send(embed=research_embed)
        await asyncio.sleep(10)
        await confirmation.delete()
        await message.delete()

async def _get_quest(ctx, name):
    channel = ctx.channel
    author = ctx.message.author.id
    return await _get_quest_v(channel, author, name)

async def _get_quest_v(channel, author, name):
    """gets a quest by name or id"""
    if not name:
        return
    id = None
    if str(name).isnumeric():
        id = int(name)
    try:
        query = QuestTable.select()
        if id is not None:
            query = query.where(QuestTable.id == id)
        query = query.execute()
        result = [d for d in query]
    except:
        return await channel.send("No quest data available!")
    if id is not None:
        return None if not result else result[0]
    quest_names = [q.name.lower() for q in result]
    if name.lower() not in quest_names:
        candidates = utils.get_match(quest_names, name, score_cutoff=60, isPartial=True, limit=20)
        name = await prompt_match_result(channel, author, name, candidates)
    return next((q for q in result if q.name.lower() == name.lower()), None)

async def _prompt_reward(ctx, quest, reward_type=None):
    channel = ctx.channel
    author = ctx.message.author.id
    return await _prompt_reward_v(channel, author, quest, reward_type)

async def _prompt_reward_v(channel, author, quest, reward_type=None):
    """prompts user for reward info selection using quest's reward pool
    can optionally specify a start point with reward_type"""
    if not quest or not quest.reward_pool:
        return
    if reward_type:
        if not reward_type in quest.reward_pool:
            raise ValueError("Starting point provided is invalid")
    else:
        candidates = [k for k, v in quest.reward_pool.items() if len(v) > 0]
        if len(candidates) == 0:
            return
        elif len(candidates) == 1:
            reward_type = candidates[0]
        else:
            prompt = "Please select a reward type:"
            reward_type = await utils.ask_list(Meowth, prompt, channel, candidates, user_list=author)
    if not reward_type:
        return
    target_pool = quest.reward_pool[reward_type]
    # handle encounters
    if reward_type == "encounters":
        return f"{', '.join([p.title() for p in target_pool])} Encounter"
    # handle items
    if reward_type == "items":
        if len(target_pool) == 1:
            target_pool = target_pool[0]
        else:
            candidates = [k for k in target_pool]
            prompt = "Please select an item:"
            reward_type = await utils.ask_list(Meowth, prompt, channel, candidates, user_list=author)
            if not reward_type:
                return
            target_pool = target_pool[reward_type]
    if len(target_pool) == 1:
        return f"{target_pool[0]} {reward_type.title()}"
    else:
        candidates = [str(q) for q in target_pool]
        prompt = "Please select the correct quantity:"
        quantity = await utils.ask_list(Meowth, prompt, channel, candidates, user_list=author)
        if not quantity:
            return
        return f"{quantity} {reward_type.title()}"

@Meowth.command(aliases=['event'])
@checks.allowmeetupreport()
async def meetup(ctx, *, location:commands.clean_content(fix_channel_mentions=True)=""):
    """Report an upcoming event.

    Usage: !meetup <location>
    Meowth will insert the details (really just everything after the species name) into a
    Google maps link and post the link to the same channel the report was made in.

    Finally, Meowth will create a separate channel for the report, for the purposes of organizing the event."""
    await _meetup(ctx, location)

async def _meetup(ctx, location):
    message = ctx.message
    channel = message.channel
    timestamp = (message.created_at + datetime.timedelta(hours=guild_dict[message.channel.guild.id]['configure_dict']['settings']['offset'])).strftime(_('%I:%M %p (%H:%M)'))
    event_split = location.split()
    if len(event_split) <= 0:
        await channel.send(_('Give more details when reporting! Usage: **!meetup <location>**'))
        return
    raid_details = ' '.join(event_split)
    raid_details = raid_details.strip()
    raid_gmaps_link = create_gmaps_query(raid_details, message.channel, type="meetup")
    raid_channel_name = _('meetup-')
    raid_channel_name += sanitize_name(raid_details)
    raid_channel_category = get_category(message.channel,"EX", category_type="meetup")
    raid_channel = await message.guild.create_text_channel(raid_channel_name, overwrites=dict(message.channel.overwrites), category=raid_channel_category)
    ow = raid_channel.overwrites_for(raid_channel.guild.default_role)
    ow.send_messages = True
    try:
        await raid_channel.set_permissions(raid_channel.guild.default_role, overwrite = ow)
    except (discord.errors.Forbidden, discord.errors.HTTPException, discord.errors.InvalidArgument):
        pass
    raid_img_url = 'https://raw.githubusercontent.com/klords/Kyogre/master/images/misc/meetup.png?cache=0'
    raid_embed = discord.Embed(title=_('Click here for directions to the event!'), url=raid_gmaps_link, colour=message.guild.me.colour)
    raid_embed.add_field(name=_('**Event Location:**'), value=raid_details, inline=True)
    raid_embed.add_field(name='\u200b', value='\u200b', inline=True)
    raid_embed.add_field(name=_('**Event Starts:**'), value=_('Set with **!starttime**'), inline=True)
    raid_embed.add_field(name=_('**Event Ends:**'), value=_('Set with **!timerset**'), inline=True)
    raid_embed.set_footer(text=_('Reported by {author} - {timestamp}').format(author=message.author.display_name, timestamp=timestamp), icon_url=message.author.avatar_url_as(format=None, static_format='jpg', size=32))
    raid_embed.set_thumbnail(url=raid_img_url)
    raidreport = await channel.send(content=_('Meetup reported by {member}! Details: {location_details}. Coordinate in {raid_channel}').format(member=message.author.display_name, location_details=raid_details, raid_channel=raid_channel.mention), embed=raid_embed)
    await asyncio.sleep(1)
    raidmsg = _("Meetup reported by {member} in {citychannel}! Details: {location_details}. Coordinate here!\n\nTo update your status, choose from the following commands: **!maybe**, **!coming**, **!here**, **!cancel**. If you are bringing more than one trainer/account, add in the number of accounts total, teams optional, on your first status update.\nExample: `!coming 5 2m 2v 1i`\n\nTo see the list of trainers who have given their status:\n**!list interested**, **!list coming**, **!list here** or use just **!list** to see all lists. Use **!list teams** to see team distribution.\n\nSometimes I'm not great at directions, but I'll correct my directions if anybody sends me a maps link or uses **!location new <address>**. You can see the location of the event by using **!location**\n\nYou can set the start time with **!starttime <MM/DD HH:MM AM/PM>** (you can also omit AM/PM and use 24-hour time) and access this with **!starttime**.\nYou can set the end time with **!timerset <MM/DD HH:MM AM/PM>** and access this with **!timer**.\n\nThis channel will be deleted five minutes after the timer expires.").format(member=message.author.display_name, citychannel=message.channel.mention, location_details=raid_details)
    raidmessage = await raid_channel.send(content=raidmsg, embed=raid_embed)
    await raidmessage.pin()
    guild_dict[message.guild.id]['raidchannel_dict'][raid_channel.id] = {
        'reportcity': channel.id,
        'trainer_dict': {},
        'exp': time.time() + (((60 * 60) * 24) * raid_info['raid_eggs']['EX']['hatchtime']),
        'manual_timer': False,
        'active': True,
        'raidmessage': raidmessage.id,
        'raidreport': raidreport.id,
        'address': raid_details,
        'type': 'egg',
        'pokemon': '',
        'egglevel': 'EX',
        'meetup': {'start':None, 'end':None},
        'reporter': message.author.id
    }
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[raid_channel.guild.id]['configure_dict']['settings']['offset'])
    await raid_channel.send(content=_('Hey {member}, if you can, set the time that the event starts with **!starttime <date and time>** and also set the time that the event ends using **!timerset <date and time>**.').format(member=message.author.mention))
    event_loop.create_task(expiry_check(raid_channel))

async def _send_notifications_async(type, details, new_channel, exclusions=[]):
    valid_types = ['raid', 'research', 'wild', 'nest', 'gym']
    if type not in valid_types:
        return
    guild = new_channel.guild
    # get trainers
    try:
        results = (SubscriptionTable
                        .select(SubscriptionTable.trainer, SubscriptionTable.target)
                        .join(TrainerTable, on=(SubscriptionTable.trainer == TrainerTable.snowflake))
                        .where((SubscriptionTable.type == type) | (SubscriptionTable.type == 'pokemon') | (SubscriptionTable.type == 'gym'))
                        .where(TrainerTable.guild == guild.id)).execute()
    except:
        return
    # group targets by trainer
    trainers = set([s.trainer for s in results])
    target_dict = {t: [s.target for s in results if s.trainer == t] for t in trainers}
    regions = set(details.get('regions', []))
    ex_eligible = details.get('ex-eligible', None)
    tier = details.get('tier', None)
    perfect = details.get('perfect', None)
    pokemon_list = details.get('pokemon', [])
    gym = details.get('location', None)
    if not isinstance(pokemon_list, list):
        pokemon_list = [pokemon_list]
    location = details.get('location', None)
    region_dict = guild_dict[guild.id]['configure_dict'].get('regions', None)
    outbound_dict = {}
    # build final dict
    for trainer in target_dict:
        user = guild.get_member(trainer)
        if trainer in exclusions or not user:
            continue
        if region_dict and region_dict.get('enabled', False):
            matched_regions = [n for n, o in region_dict.get('info', {}).items() if o['role'] in [r.name for r in user.roles]]
            if regions and regions.isdisjoint(matched_regions):
                continue
        targets = target_dict[trainer]
        descriptors = []
        target_matched = False
        if 'ex-eligible' in targets and ex_eligible:
            target_matched = True
            descriptors.append('ex-eligible')
        if tier and tier in targets:
            target_matched = True
            descriptors.append('level {level}'.format(level=details['tier']))
        pkmn_adj = ''
        if perfect and 'perfect' in targets:
            target_matched = True
            pkmn_adj = 'perfect '
        for pokemon in pokemon_list:
            if pokemon.name in targets:
                target_matched = True
            full_name = pkmn_adj + pokemon.name
            descriptors.append(full_name)
        if gym in targets:
            target_matched = True
        if not target_matched:
            continue
        description = ', '.join(descriptors)
        start = 'An' if re.match(r'^[aeiou]', description, re.I) else 'A'
        message = '**New {title_type}**! {start} {description} {type} at {location} has been reported! For more details, go to the {mention} channel!'.format(title_type=type.title(), start=start, description=description, type=type, location=location, mention=new_channel.mention)
        outbound_dict[trainer] = {'discord_obj': user, 'message': message}
    pokemon_names = ' '.join([p.name for p in pokemon_list])
    role_name = sanitize_name(f"{type} {pokemon_names} {location}".title())
    return await _generate_role_notification_async(role_name, new_channel, outbound_dict)

async def _generate_role_notification_async(role_name, channel, outbound_dict):
    '''Generates and handles a temporary role notification in the new raid channel'''
    if len(outbound_dict) == 0:
        return
    guild = channel.guild
    # generate new role
    temp_role = await guild.create_role(name=role_name, hoist=False, mentionable=True)
    for trainer in outbound_dict.values():
        await trainer['discord_obj'].add_roles(temp_role)
    # send notification message in channel
    obj = next(iter(outbound_dict.values()))
    message = obj['message']
    msg_obj = await channel.send(f'{temp_role.mention} {message}')
    async def cleanup():
        await asyncio.sleep(300)
        await temp_role.delete()
        await msg_obj.delete()
    asyncio.ensure_future(cleanup())

"""
Data Management Commands
"""

@Meowth.group(name="reports")
@commands.has_permissions(manage_guild=True)
async def _reports(ctx):
    """Report data management command"""
    if ctx.invoked_subcommand == None:
        raise commands.BadArgument()

@_reports.command(name="list", aliases=["ls"])
async def _reports_list(ctx, *, type, regions=''):
    """Lists the current active reports of the specified type, optionally for one or more regions"""
    valid_types = ['raid', 'research']
    channel = ctx.channel
    type = type.lower()
    if type not in valid_types:
        await channel.send(f"'{type}' is either invalid or unsupported. Please use one of the following: {', '.join(valid_types)}")
    await ctx.channel.send(f"This is a {type} listing")

@Meowth.group(name="quest")
async def _quest(ctx):
    """Quest data management command"""
    if ctx.invoked_subcommand == None:
        raise commands.BadArgument()

@_quest.command(name="info", aliases=["lookup", "get", "find"])
@checks.allowresearchreport()
async def _quest_info(ctx, *, name):
    """Look up a quest by name, returning the quest ID and details
    
    Usage: !quest info <name>"""
    channel = ctx.channel
    quest = await _get_quest(ctx, name)
    if not quest:
        return await channel.send("Unable to find quest by that name")
    await channel.send(format_quest_info(quest))

@_quest.command(name="add")
@commands.has_permissions(manage_guild=True)
async def _quest_add(ctx, *, info):
    """Add a new quest and associated reward pool, separated by comma.
    
    Usage: !quest add <name>[, reward_pool]
    
    Reward pool should be provided as a JSON string. If not provided, an empty default will be used."""
    channel = ctx.channel
    name = None
    pool = None
    if ',' in info:
        name, pool = info.split(',', 1)
    else:
        name = info
    if '{' in name:
        return await channel.send('Please check the format of your message and try again. The name and reward pool should be separated by a comma')
    if pool:
        try:
            pool = json.loads(pool)
        except ValueError:
            return await channel.send("Error: provided reward pool is not a valid JSON string")
    try:
        new_quest = QuestTable.create(name=name, reward_pool=pool if pool else {})
    except:
        return await channel.send("Unable to add record. Please ensure the quest does not already exist with the find command.")
    await channel.send(f"Successfully added new quest: {new_quest.name} ({new_quest.id})")

@_quest.command(name="remove", aliases=["rm", "delete", "del"])
@commands.has_permissions(manage_guild=True)
async def _quest_remove(ctx, id):
    """Remove a quest by its ID
    
    Usage: !quest remove <id>"""
    channel = ctx.channel

    try:
        deleted = QuestTable.delete().where(QuestTable.id == id).execute()
    except:
        deleted = False
    
    if deleted:
        return await channel.send("Successfully deleted record")
    return await channel.send("Unable to delete record")

def format_quest_info(quest):
    pool = quest.reward_pool
    output = f"{quest.name} ({quest.id})\n"
    encounters = pool.get('encounters', [])
    stardust = pool.get('stardust', [])
    xp = pool.get('xp', [])
    items = pool.get('items', {})
    if encounters:
        encounters = [str(e) for e in encounters]
        output += f"\nEncounters: {', '.join(encounters).title()}"
    if stardust:
        stardust = [str(s) for s in stardust]
        output += f"\nStardust: {', '.join(stardust)}"
    if xp:
        xp = [str(x) for x in xp]
        output += f"\nExperience: {', '.join(xp)}"
    if items:
        output += "\nItems:"
        for name, quantities in items.items():
            output += f"\n\t{name.title()}: {quantities[0] if len(quantities) == 1 else quantities[0] + ' - ' + quantities[-1]}"
    return output

@Meowth.group(name="rewards")
@commands.has_permissions(manage_guild=True)
async def _rewards(ctx):
    """Quest reward pool data management command"""
    if ctx.invoked_subcommand == None:
        raise commands.BadArgument()

@_rewards.command(name="add")
async def _rewards_add(ctx, *, info):
    """Adds a reward to reward pool for a given quest using provided comma-separated values.
    
    Usage: !rewards add <ID>, <type>, <value>
    
    ID must correspond to a valid db entry.
    If type is not encounters, stardust, or xp, it will be assumed to be an item."""
    channel = ctx.channel
    try:
        id, type, value = re.split(r'\s*,\s*', info)
        id = int(id)
        type = type.lower()
    except:
        return await channel.send("Error parsing input. Please check the format and try again")
    try:
        quest = QuestTable[id]
    except:
        return await channel.send(f"Unable to get quest with id {id}")
    pool = quest.reward_pool
    if type.startswith("encounter"):
        pokemon = Pokemon.get_pokemon(Meowth, value)
        if pokemon:
            pool.setdefault("encounters", []).append(pokemon.name.lower())
    else:
        if not value.isnumeric():
            return await channel.send("Value must be a numeric quantity")
        if type == "stardust":
            pool.setdefault("stardust", []).append(int(value))
        elif type == "xp":
            pool.setdefault("xp", []).append(int(value))
        else:
            pool.setdefault("items", {}).setdefault(type, []).append(int(value))
    quest.reward_pool = pool
    quest.save()
    await channel.send("Successfully added reward to pool")

@_rewards.command(name="remove", aliases=["rm", "delete", "del"])
async def _rewards_remove(ctx, *, info):
    """Removes a reward to reward pool for a given quest using provided comma-separated values.
    
    Usage: !rewards remove <ID>, <type>, <value>
    
    ID must correspond to a valid db entry.
    If type is not encounters, stardust, or xp, it will be assumed to be an item."""
    channel = ctx.channel
    try:
        id, type, value = re.split(r'\s*,\s*', info)
        id = int(id)
        type = type.lower()
    except:
        return await channel.send("Error parsing input. Please check the format and try again")
    try:
        quest = QuestTable[id]
    except:
        return await channel.send(f"Unable to get quest with id {id}")
    pool = quest.reward_pool
    if type.startswith("encounter"):
        pokemon = Pokemon.get_pokemon(Meowth, value)
        name = pokemon.name.lower()
        if pokemon:
            try:
                pool["encounters"].remove(name)
            except:
                return await channel.send(f"Unable to remove {value}")
    else:
        if not value.isnumeric():
            return await channel.send("Value must be a numeric quantity")
        try:
            if type == "stardust":
                pool["stardust"].remove(int(value))
            elif type == "xp":
                pool["xp"].remove(int(value))
            else:
                pool["items"][type].remove(int(value))
                if len(pool["items"][type]) == 0:
                    del pool["items"][type]
        except:
            return await channel.send(f"Unable to remove {value}")
    quest.reward_pool = pool
    quest.save()
    await channel.send("Successfully removed reward from pool")


@Meowth.command(name="refresh_listings", hidden=True)
@commands.has_permissions(manage_guild=True)
async def _refresh_listing_channels(ctx, type, *, regions=None):
    if regions:
        regions = [r.strip() for r in regions.split(',')]
    await _update_listing_channels(ctx.guild, type, edit=True, regions=regions)
    await ctx.message.add_reaction('\u2705')

async def _refresh_listing_channels_internal(guild, type, *, regions=None):
    if regions:
        regions = [r.strip() for r in regions.split(',')]
    await _update_listing_channels(guild, type, edit=True, regions=regions)

async def _update_listing_channels(guild, type, edit=False, regions=None):
    valid_types = ['raid', 'research', 'wild', 'nest']
    if type not in valid_types:
        return
    listing_dict = guild_dict[guild.id]['configure_dict'].get(type, {}).get('listings', None)
    if not listing_dict or not listing_dict['enabled']:
        return
    if 'channel' in listing_dict:
        channel = Meowth.get_channel(listing_dict['channel']['id'])
        return await _update_listing_channel(channel, type, edit)
    if 'channels' in listing_dict:
        if not regions:
            regions = [r for r in listing_dict['channels']]
        for region in regions:
            channel_list = listing_dict['channels'].get(region, [])
            if not isinstance(channel_list, list):
                channel_list = [channel_list]
            for channel_info in channel_list:
                channel = Meowth.get_channel(channel_info['id'])
                await _update_listing_channel(channel, type, edit, region=region)

async def _update_listing_channel(channel, type, edit, region=None):
    lock = asyncio.Lock()
    async with lock:
        listing_dict = guild_dict[channel.guild.id]['configure_dict'].get(type, {}).get('listings', None)
        if not listing_dict or not listing_dict['enabled']:
            return
        new_messages = await _get_listing_messages(type, channel, region)
        previous_messages = await _get_previous_listing_messages(type, channel, region)
        matches = itertools.zip_longest(new_messages, previous_messages)
        new_ids = []
        for pair in matches:
            new_message = pair[0]
            old_message = pair[1]
            if pair[1]:
                try:
                    old_message = await channel.get_message(old_message)
                except:
                    old_message = None
            if new_message:
                new_embed = discord.Embed(description=new_message, colour=channel.guild.me.colour)
                if old_message:
                    if edit:
                        await old_message.edit(embed=new_embed)
                        new_ids.append(old_message.id)
                        continue
                    else:
                        await old_message.delete()
                new_message_obj = await channel.send(embed=new_embed)
                new_ids.append(new_message_obj.id)
            else: # old_message must be something if new_message is nothing
                await old_message.delete()
        if 'channel' in listing_dict:
            listing_dict['channel']['messages'] = new_ids
        elif 'channels' in listing_dict:
            listing_dict['channels'][region]['messages'] = new_ids
        guild_dict[channel.guild.id]['configure_dict'][type]['listings'] = listing_dict

async def _get_previous_listing_messages(type, channel, region=None):
    listing_dict = guild_dict[channel.guild.id]['configure_dict'].get(type, {}).get('listings', None)
    if not listing_dict or not listing_dict['enabled']:
        return
    previous_messages = []
    if 'channel' in listing_dict:
        previous_messages = listing_dict['channel'].get('messages', [])
    elif 'channels' in listing_dict:
        if region:
            previous_messages = listing_dict['channels'].get(region, {}).get('messages', [])
        else:
            for region, channel_info in listing_dict['channels'].items():
                if channel_info['id'] == channel.id:
                    previous_messages = channel_info.get('messages', [])
                    break
    else:
        message_history = []
        message_history = await channel.history(reverse=True).flatten()
        if len(message_history) >= 1:
            search_text = f"active {type}"
            for message in message_history:
                if search_text in message.embeds[0].description.lower():
                    previous_messages.append(message.id)
                    break
    return previous_messages

async def _get_listing_messages(type, channel, region=None):
    if type == 'raid':
        return await _get_raid_listing_messages(channel, region)
    elif type == 'wild':
        return await _get_wild_listing_messages(channel, region)
    elif type == 'research':
        return await _get_research_listing_messages(channel, region)
    else:
        return None

def _get_channel_regions(channel, type):
    regions = None
    config_dict = guild_dict[channel.guild.id]['configure_dict']
    if config_dict.get(type, {}).get('enabled', None):
        regions = config_dict.get(type, {}).get('report_channels', {}).get(channel.id, None)
        if regions and not isinstance(regions, list):
            regions = [regions]
    if type == "raid":
        cat_dict = config_dict.get(type, {}).get('category_dict', {})
        for r in cat_dict:
            if cat_dict[r] == channel.category.id:
                regions = [config_dict.get(type, {}).get('report_channels', {}).get(r, None)]
    if len(regions) < 1:
        return []
    else:
        return list(set(regions))

"""
Raid Channel Management
"""

async def print_raid_timer(channel):
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[channel.guild.id]['configure_dict']['settings']['offset'])
    end = now + datetime.timedelta(seconds=guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['exp'] - time.time())
    timerstr = ' '
    if guild_dict[channel.guild.id]['raidchannel_dict'][channel.id].get('meetup',{}):
        end = guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['meetup']['end']
        start = guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['meetup']['start']
        if guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['type'] == 'egg':
            if start:
                timerstr += _("This event will start at {expiry_time}").format(expiry_time=start.strftime(_('%B %d at %I:%M %p (%H:%M)')))
            else:
                timerstr += _("Nobody has told me a start time! Set it with **!starttime**")
            if end:
                timerstr += _(" | This event will end at {expiry_time}").format(expiry_time=end.strftime(_('%B %d at %I:%M %p (%H:%M)')))
        if guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['type'] == 'exraid':
            if end:
                timerstr += _("This event will end at {expiry_time}").format(expiry_time=end.strftime(_('%B %d at %I:%M %p (%H:%M)')))
            else:
                timerstr += _("Nobody has told me a end time! Set it with **!timerset**")
        return timerstr
    if guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['type'] == 'egg':
        raidtype = _('egg')
        raidaction = _('hatch')
    else:
        raidtype = _('raid')
        raidaction = _('end')
    if (not guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['active']):
        timerstr += _("This {raidtype}'s timer has already expired as of {expiry_time}!").format(raidtype=raidtype, expiry_time=end.strftime(_('%I:%M %p (%H:%M)')))
    elif (guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['egglevel'] == 'EX') or (guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['type'] == 'exraid'):
        if guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['manual_timer']:
            timerstr += _('This {raidtype} will {raidaction} on {expiry}!').format(raidtype=raidtype, raidaction=raidaction, expiry=end.strftime(_('%B %d at %I:%M %p (%H:%M)')))
        else:
            timerstr += _("No one told me when the {raidtype} will {raidaction}, so I'm assuming it will {raidaction} on {expiry}!").format(raidtype=raidtype, raidaction=raidaction, expiry=end.strftime(_('%B %d at %I:%M %p (%H:%M)')))
    elif guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['manual_timer']:
        timerstr += _('This {raidtype} will {raidaction} at {expiry_time}!').format(raidtype=raidtype, raidaction=raidaction, expiry_time=end.strftime(_('%I:%M %p (%H:%M)')))
    else:
        timerstr += _("No one told me when the {raidtype} will {raidaction}, so I'm assuming it will {raidaction} at {expiry_time}!").format(raidtype=raidtype, raidaction=raidaction, expiry_time=end.strftime(_('%I:%M %p (%H:%M)')))
    return timerstr

async def raid_time_check(channel,time):
    if time.isdigit():
        raidexp = int(time)
        return raidexp
    elif ':' in time:
        now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[channel.guild.id]['configure_dict']['settings']['offset'])
        start = dateparser.parse(time, settings={'PREFER_DATES_FROM': 'future'})
        start = start.replace(month = now.month, day=now.day, year=now.year)
        timediff = relativedelta(start, now)
        if timediff.hours <= -10:
            start = start + datetime.timedelta(hours=12)
            timediff = relativedelta(start, now)
        raidexp = (timediff.hours*60) + timediff.minutes + 1
        if raidexp < 0:
            return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description='Please enter a time in the future.'))
            return False
        return raidexp
    else:
        return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description="I couldn't understand your time format. Try again like this: **!timerset <minutes>**"))
        return False

@Meowth.command()
@checks.raidchannel()
async def timerset(ctx, *,timer):
    """Set the remaining duration on a raid.

    Usage: !timerset <minutes>
    Works only in raid channels, can be set or overridden by anyone.
    Kyogre displays the end time in HH:MM local time."""
    message = ctx.message
    channel = message.channel
    guild = message.guild
    author = message.author
    hourminute = False
    type = guild_dict[guild.id]['raidchannel_dict'][channel.id]['type']
    if (not checks.check_exraidchannel(ctx)) and not (checks.check_meetupchannel(ctx)):
        if type == 'egg':
            raidlevel = guild_dict[guild.id]['raidchannel_dict'][channel.id]['egglevel']
            raidtype = _('Raid Egg')
            maxtime = raid_info['raid_eggs'][raidlevel]['hatchtime']
        else:
            raidlevel = utils.get_level(Meowth, guild_dict[guild.id]['raidchannel_dict'][channel.id]['pokemon'])
            raidtype = _('Raid')
            maxtime = raid_info['raid_eggs'][raidlevel]['raidtime']
        raidexp = False
        if timer.isdigit() or ':' in timer:
            raidexp = await raid_time_check(channel,timer)
            if raidexp is False:
                return
            if _timercheck(raidexp, maxtime):
                return await channel.send(embed=discord.Embed(colour=discord.Colour.red(), description=f"That's too long. Level {raidlevel} {raidtype.capitalize()}s currently last no more than {maxtime} minutes."))
        await _timerset(channel, raidexp)
    if checks.check_exraidchannel(ctx):
        if checks.check_eggchannel(ctx) or checks.check_meetupchannel(ctx):
            now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])
            timer_split = timer.lower().split()
            try:
                start = dateparser.parse(' '.join(timer_split).lower(), settings={'DATE_ORDER': 'MDY'})
            except:
                if ('am' in ' '.join(timer_split).lower()) or ('pm' in ' '.join(timer_split).lower()):
                    try:
                        start = datetime.datetime.strptime((' '.join(timer_split) + ' ') + str(now.year), '%m/%d %I:%M %p %Y')
                        if start.month < now.month:
                            start = start.replace(year=now.year + 1)
                    except ValueError:
                        await channel.send(_("Your timer wasn't formatted correctly. Change your **!timerset** to match this format: **MM/DD HH:MM AM/PM** (You can also omit AM/PM and use 24-hour time!)"))
                        return
                else:
                    try:
                        start = datetime.datetime.strptime((' '.join(timer_split) + ' ') + str(now.year), '%m/%d %H:%M %Y')
                        if start.month < now.month:
                            start = start.replace(year=now.year + 1)
                    except ValueError:
                        await channel.send(_("Your timer wasn't formatted correctly. Change your **!timerset** to match this format: **MM/DD HH:MM AM/PM** (You can also omit AM/PM and use 24-hour time!)"))
                        return
            if checks.check_meetupchannel(ctx):
                starttime = guild_dict[guild.id]['raidchannel_dict'][channel.id]['meetup'].get('start',False)
                if starttime and start < starttime:
                    await channel.send(_('Please enter a time after your start time.'))
                    return
            diff = start - now
            total = diff.total_seconds() / 60
            if now <= start:
                await _timerset(channel, total)
            elif now > start:
                await channel.send(_('Please enter a time in the future.'))
        else:
            await channel.send(_("Timerset isn't supported for EX Raids after they have hatched."))

def _timercheck(time, maxtime):
    return time > maxtime

async def _timerset(raidchannel, exptime):
    guild = raidchannel.guild
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])
    end = now + datetime.timedelta(minutes=exptime)
    guild_dict[guild.id]['raidchannel_dict'][raidchannel.id]['exp'] = time.time() + (exptime * 60)
    if (not guild_dict[guild.id]['raidchannel_dict'][raidchannel.id]['active']):
        await raidchannel.send(_('The channel has been reactivated.'))
    guild_dict[guild.id]['raidchannel_dict'][raidchannel.id]['active'] = True
    guild_dict[guild.id]['raidchannel_dict'][raidchannel.id]['manual_timer'] = True
    topicstr = ''
    if guild_dict[guild.id]['raidchannel_dict'][raidchannel.id].get('meetup',{}):
        guild_dict[guild.id]['raidchannel_dict'][raidchannel.id]['meetup']['end'] = end
        topicstr += _('Ends on {end}').format(end=end.strftime(_('%B %d at %I:%M %p (%H:%M)')))
        endtime = end.strftime(_('%B %d at %I:%M %p (%H:%M)'))
    elif guild_dict[guild.id]['raidchannel_dict'][raidchannel.id]['type'] == 'egg':
        egglevel = guild_dict[guild.id]['raidchannel_dict'][raidchannel.id]['egglevel']
        hatch = end
        end = hatch + datetime.timedelta(minutes=raid_info['raid_eggs'][egglevel]['raidtime'])
        topicstr += _('Hatches on {expiry}').format(expiry=hatch.strftime(_('%B %d at %I:%M %p (%H:%M) | ')))
        topicstr += _('Ends on {end}').format(end=end.strftime(_('%B %d at %I:%M %p (%H:%M)')))
        endtime = hatch.strftime(_('%B %d at %I:%M %p (%H:%M)'))
    else:
        topicstr += _('Ends on {end}').format(end=end.strftime(_('%B %d at %I:%M %p (%H:%M)')))
        endtime = end.strftime(_('%B %d at %I:%M %p (%H:%M)'))
    timerstr = await print_raid_timer(raidchannel)
    await raidchannel.send(timerstr)
    await raidchannel.edit(topic=topicstr)
    report_channel = Meowth.get_channel(guild_dict[guild.id]['raidchannel_dict'][raidchannel.id]['reportcity'])
    raidmsg = await raidchannel.get_message(guild_dict[guild.id]['raidchannel_dict'][raidchannel.id]['raidmessage'])
    reportmsg = await report_channel.get_message(guild_dict[guild.id]['raidchannel_dict'][raidchannel.id]['raidreport'])
    embed = raidmsg.embeds[0]
    index = 0
    found = False
    for field in embed.fields:
        if "hatches" in field.name.lower():
            found = True
            break
        index += 1
    if found:
        embed.set_field_at(index, name=embed.fields[index].name, value=endtime, inline=True)
    else:
        if guild_dict[guild.id]['raidchannel_dict'][raidchannel.id]['type'] == "raid":
            embed.add_field(name=_('**Expires:**'), value=endtime, inline=True)
        else:
            embed.add_field(name=_('**Hatches:**'), value=endtime, inline=True)
    try:
        await raidmsg.edit(content=raidmsg.content,embed=embed)
    except discord.errors.NotFound:
        pass
    try:
        await reportmsg.edit(content=reportmsg.content,embed=embed)
    except discord.errors.NotFound:
        pass
    await _update_listing_channels(raidchannel.guild, 'raid', edit=True, regions=guild_dict[guild.id]['raidchannel_dict'][raidchannel.id].get('regions', None))
    raidchannel = Meowth.get_channel(raidchannel.id)
    event_loop.create_task(expiry_check(raidchannel))

@Meowth.command()
@checks.raidchannel()
async def timer(ctx):
    """Have Kyogre resend the expire time message for a raid.

    Usage: !timer
    The expiry time should have been previously set with !timerset."""
    timerstr = await print_raid_timer(ctx.channel)
    await ctx.channel.send(timerstr)

@Meowth.command()
@checks.activechannel()
async def starttime(ctx,*,start_time=""):
    """Set a time for a group to start a raid

    Usage: !starttime [HH:MM AM/PM]
    (You can also omit AM/PM and use 24-hour time!)
    Works only in raid channels. Sends a message and sets a group start time that
    can be seen using !starttime (without a time). One start time is allowed at
    a time and is visibile in !list output. Cleared with !starting."""
    message = ctx.message
    guild = message.guild
    channel = message.channel
    author = message.author
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])
    start_split = start_time.lower().split()
    rc_d = guild_dict[guild.id]['raidchannel_dict'][channel.id]
    timeset = False
    start = None
    if rc_d.get('meetup',{}):
        try:
            start = dateparser.parse(' '.join(start_split).lower(), settings={'DATE_ORDER': 'MDY'})
            endtime = guild_dict[guild.id]['raidchannel_dict'][channel.id]['meetup'].get('end',False)
            if start < now:
                await channel.send(_('Please enter a time in the future.'))
                return
            if endtime and start > endtime:
                await channel.send(_('Please enter a time before your end time.'))
                return
            timeset = True
            rc_d['meetup']['start'] = start
        except:
            pass
    if not timeset:
        if rc_d['type'] == 'egg':
            egglevel = rc_d['egglevel']
            mintime = (rc_d['exp'] - time.time()) / 60
            maxtime = mintime + raid_info['raid_eggs'][egglevel]['raidtime']
        elif (rc_d['type'] == 'raid') or (rc_d['type'] == 'exraid'):
            egglevel = utils.get_level(Meowth, rc_d['pokemon'])
            mintime = 0
            maxtime = (rc_d['exp'] - time.time()) / 60
        if len(start_split) > 0:
            alreadyset = rc_d.get('starttime',False)
            if ('am' in ' '.join(start_split).lower()) or ('pm' in ' '.join(start_split).lower()):
                try:
                    start = datetime.datetime.strptime(' '.join(start_split), '%I:%M %p').replace(year=now.year, month=now.month, day=now.day)
                except ValueError:
                    await channel.send(_("Your start time wasn't formatted correctly. Change your **!starttime** to match this format: **HH:MM AM/PM** (You can also omit AM/PM and use 24-hour time!)"))
                    return
            else:
                try:
                    start = datetime.datetime.strptime(' '.join(start_split), '%H:%M').replace(year=now.year, month=now.month, day=now.day)
                except ValueError:
                    await channel.send(_("Your start time wasn't formatted correctly. Change your **!starttime** to match this format: **HH:MM AM/PM** (You can also omit AM/PM and use 24-hour time!)"))
                    return
            if egglevel == 'EX':
                hatch = datetime.datetime.utcfromtimestamp(rc_d['exp']) + datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])
                start = start.replace(year=hatch.year, month=hatch.month, day=hatch.day)
            diff = start - now
            total = diff.total_seconds() / 60
            if total > maxtime and egglevel != 'EX':
                await channel.send(_('The raid will be over before that....'))
                return
            if now > start and egglevel != 'EX':
                await channel.send(_('Please enter a time in the future.'))
                return
            if int(total) < int(mintime) and egglevel != 'EX':
                await channel.send(_('The egg will not hatch by then!'))
                return
            if alreadyset:
                rusure = await channel.send(_('There is already a start time of **{start}** set! Do you want to change it?').format(start=alreadyset.strftime(_('%I:%M %p (%H:%M)'))))
                try:
                    timeout = False
                    res, reactuser = await ask(rusure, channel, author.id)
                except TypeError:
                    timeout = True
                if timeout or res.emoji == '❎':
                    await rusure.delete()
                    confirmation = await channel.send(_('Start time change cancelled.'))
                    await asyncio.sleep(10)
                    await confirmation.delete()
                    return
                elif res.emoji == '✅':
                    await rusure.delete()
                    if now <= start:
                        timeset = True
                else:
                    return
    if (start and now <= start) or timeset:
        rc_d['starttime'] = start
        nextgroup = start.strftime(_('%I:%M %p (%H:%M)'))
        if rc_d.get('meetup',{}):
            nextgroup = start.strftime(_('%B %d at %I:%M %p (%H:%M)'))
        await channel.send(_('The current start time has been set to: **{starttime}**').format(starttime=nextgroup))
        report_channel = Meowth.get_channel(rc_d['reportcity'])
        raidmsg = await channel.get_message(rc_d['raidmessage'])
        reportmsg = await report_channel.get_message(rc_d['raidreport'])
        embed = raidmsg.embeds[0]
        embed.set_field_at(2, name=embed.fields[2].name, value=nextgroup, inline=True)
        try:
            await raidmsg.edit(content=raidmsg.content,embed=embed)
        except discord.errors.NotFound:
            pass
        try:
            await reportmsg.edit(content=reportmsg.content,embed=embed)
        except discord.errors.NotFound:
            pass
        return
    else:
        starttime = rc_d.get('starttime',None)
        if starttime and starttime < now:
            rc_d['starttime'] = None
            starttime = None
        if starttime:
            await channel.send(_('The current start time is: **{starttime}**').format(starttime=starttime.strftime(_('%I:%M %p (%H:%M)'))))
        elif not starttime:
            await channel.send(_('No start time has been set, set one with **!starttime HH:MM AM/PM**! (You can also omit AM/PM and use 24-hour time!)'))

@Meowth.group(case_insensitive=True)
@checks.activechannel()
async def location(ctx):
    """Get raid location.

    Usage: !location
    Works only in raid channels. Gives the raid location link."""
    if ctx.invoked_subcommand == None:
        message = ctx.message
        guild = message.guild
        channel = message.channel
        rc_d = guild_dict[guild.id]['raidchannel_dict']
        raidmsg = await channel.get_message(rc_d[channel.id]['raidmessage'])
        location = rc_d[channel.id]['address']
        report_channel = Meowth.get_channel(rc_d[channel.id]['reportcity'])
        oldembed = raidmsg.embeds[0]
        locurl = oldembed.url
        newembed = discord.Embed(title=oldembed.title, url=locurl, colour=guild.me.colour)
        for field in oldembed.fields:
            newembed.add_field(name=field.name, value=field.value, inline=field.inline)
        newembed.set_footer(text=oldembed.footer.text, icon_url=oldembed.footer.icon_url)
        newembed.set_thumbnail(url=oldembed.thumbnail.url)
        locationmsg = await channel.send(content=_("Here's the current location for the raid!\nDetails: {location}").format(location=location), embed=newembed)
        await asyncio.sleep(60)
        await locationmsg.delete()

@location.command()
@checks.activechannel()
async def new(ctx,*,content):
    """Change raid location.

    Usage: !location new <gym name>
    Works only in raid channels. Updates the gym at which the raid is located."""
    message = ctx.message
    channel = message.channel
    location_split = content.lower().split()
    if len(location_split) < 1:
        await channel.send(_("We're missing the new location details! Usage: **!location new <new address>**"))
        return
    else:
        report_channel = Meowth.get_channel(guild_dict[message.guild.id]['raidchannel_dict'][channel.id]['reportcity'])
        if not report_channel:
            async for m in channel.history(limit=500, reverse=True):
                if m.author.id == message.guild.me.id:
                    c = _('Coordinate here')
                    if c in m.content:
                        report_channel = m.raw_channel_mentions[0]
                        break
        details = ' '.join(location_split)
        config_dict = guild_dict[message.guild.id]['configure_dict']
        regions = _get_channel_regions(channel, 'raid')
        gym = None
        gyms = get_gyms(message.guild.id, regions)
        if gyms:
            gym = await location_match_prompt(channel, message.author.id, details, gyms)
            if not gym:
                return await channel.send(_("I couldn't find a gym named '{0}'. Try again using the exact gym name!").format(details))
            details = gym.name
            newloc = gym.maps_url
            regions = [gym.region]
        else:
            newloc = create_gmaps_query(details, report_channel, type="raid")
        await update_raid_location(message, report_channel, channel, gym)
        return

async def update_raid_location(message, report_channel, raid_channel, gym):
    guild = message.guild
    oldraidmsg = await raid_channel.get_message(guild_dict[guild.id]['raidchannel_dict'][raid_channel.id]['raidmessage'])
    oldreportmsg = await report_channel.get_message(guild_dict[guild.id]['raidchannel_dict'][raid_channel.id]['raidreport'])
    oldembed = oldraidmsg.embeds[0]
    newloc = gym.maps_url
    regions = [gym.region]
    newembed = discord.Embed(title=oldembed.title, url=newloc, colour=guild.me.colour)
    for field in oldembed.fields:
        t = _('team')
        s = _('status')
        if (t not in field.name.lower()) and (s not in field.name.lower()):
            if "gym" in field.name.lower():
                gym_info = _("**Name:** {0}\n**Notes:** {1}").format(gym.name, "_EX Eligible Gym_" if gym.ex_eligible else "N/A")
                newembed.add_field(name=_('**Gym:**'), value=gym_info, inline=field.inline)
            else:
                newembed.add_field(name=field.name, value=field.value, inline=field.inline)
    newembed.set_footer(text=oldembed.footer.text, icon_url=oldembed.footer.icon_url)
    newembed.set_thumbnail(url=oldembed.thumbnail.url)
    otw_list = []
    trainer_dict = copy.deepcopy(guild_dict[guild.id]['raidchannel_dict'][raid_channel.id]['trainer_dict'])
    for trainer in trainer_dict.keys():
        if trainer_dict[trainer]['status']['coming']:
            user = guild.get_member(trainer)
            otw_list.append(user.mention)
    await raid_channel.send(content=_('Someone has suggested a different location for the raid! Trainers {trainer_list}: make sure you are headed to the right place!').format(trainer_list=', '.join(otw_list)), embed=newembed)
    for field in oldembed.fields:
        t = _('team')
        s = _('status')
        if (t in field.name.lower()) or (s in field.name.lower()):
            newembed.add_field(name=field.name, value=field.value, inline=field.inline)
    try:
        await oldraidmsg.edit(new_content=oldraidmsg.content, embed=newembed, content=oldraidmsg.content)
    except:
        pass
    try:
        await oldreportmsg.edit(new_content=oldreportmsg.content, embed=newembed, content=oldreportmsg.content)
    except:
        pass
    temp = guild_dict[guild.id]['raidchannel_dict'][raid_channel.id]
    temp['raidmessage'] = oldraidmsg.id
    temp['raidreport'] = oldreportmsg.id
    temp['gym'] = gym
    temp['address'] = gym.name
    temp['regions'] = regions
    guild_dict[guild.id]['raidchannel_dict'][raid_channel.id] = temp
    channel_name = raid_channel.name
    channel_prefix = channel_name.split("_")[0]
    new_channel_name = sanitize_name(channel_prefix + "_"+ gym.name)
    await raid_channel.edit(name=new_channel_name)
    await _update_listing_channels(guild, "raid", True)
    return

@Meowth.command()
async def recover(ctx):
    """Recover a raid channel if it is no longer responding to commands

    Usage: !recover
    Only necessary after a crash."""
    if (checks.check_subscriptionchannel(ctx) or checks.check_citychannel(ctx) or checks.check_raidchannel(ctx) or checks.check_eggchannel(ctx) or checks.check_exraidchannel(ctx)):
        await ctx.channel.send(_("I can't recover this channel because I know about it already!"))
    else:
        channel = ctx.channel
        guild = channel.guild
        name = channel.name
        topic = channel.topic
        h = _('hatched-')
        e = _('expired-')
        while h in name or e in name:
            name = name.replace(h,'')
            name = name.replace(e,'')
        egg = re.match(_('[1-5]-egg'), name)
        meetup = re.match(_('meetup'), name)
        now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])
        reportchannel = None
        raidmessage = None
        trainer_dict = {}
        name_split = name.replace('-', ' ').split('_')
        pokemon = name_split[0]
        async for message in channel.history(limit=500, reverse=True):
            if message.author.id == guild.me.id:
                c = _('Coordinate here')
                if c in message.content:
                    reportchannel = message.raw_channel_mentions[0]
                    raidmessage = message
                    break
        if egg:
            raidtype = 'egg'
            chsplit = egg.string.split('-')
            del chsplit[0]
            egglevel = chsplit[0]
            del chsplit[0]
            del chsplit[0]
            raid_details = ' '.join(chsplit)
            raid_details = raid_details.strip()
            if (not topic):
                exp = raidmessage.created_at.replace(tzinfo=datetime.timezone.utc).timestamp() + (60 * raid_info['raid_eggs'][egglevel]['hatchtime'])
                manual_timer = False
            else:
                topicsplit = topic.split('|')
                localhatch = datetime.datetime.strptime(topicsplit[0][:(- 9)], 'Hatches on %B %d at %I:%M %p')
                utchatch = localhatch - datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])
                exp = utchatch.replace(year=now.year, tzinfo=datetime.timezone.utc).timestamp()
                manual_timer = True
            pokemon = ''
            if len(raid_info['raid_eggs'][egglevel]['pokemon']) == 1:
                pokemon = raid_info['raid_eggs'][egglevel]['pokemon'][0]
        elif pokemon in get_raidlist():
            raidtype = 'raid'
            egglevel = '0'
            raid_details = ' '.join(name_split[1:])
            raid_details = raid_details.strip()
            if (not topic):
                exp = raidmessage.created_at.replace(tzinfo=datetime.timezone.utc).timestamp() + (60 * raid_info['raid_eggs'][utils.get_level(Meowth, pokemon)]['raidtime'])
                manual_timer = False
            else:
                localend = datetime.datetime.strptime(topic[:(- 8)], _('Ends on %B %d at %I:%M %p'))
                utcend = localend - datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])
                exp = utcend.replace(year=now.year, tzinfo=datetime.timezone.utc).timestamp()
                manual_timer = True
        elif name.split('-')[0] == 'ex':
            raidtype = 'egg'
            egglevel = 'EX'
            chsplit = name.split('-')
            del chsplit[0]
            del chsplit[0]
            del chsplit[0]
            raid_details = ' '.join(chsplit)
            raid_details = raid_details.strip()
            if (not topic):
                exp = raidmessage.created_at.replace(tzinfo=datetime.timezone.utc).timestamp() + (((60 * 60) * 24) * 14)
                manual_timer = False
            else:
                topicsplit = topic.split('|')
                localhatch = datetime.datetime.strptime(topicsplit[0][:(- 9)], 'Hatches on %B %d at %I:%M %p')
                utchatch = localhatch - datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])
                exp = utchatch.replace(year=now.year, tzinfo=datetime.timezone.utc).timestamp()
                manual_timer = True
            pokemon = ''
            if len(raid_info['raid_eggs']['EX']['pokemon']) == 1:
                pokemon = raid_info['raid_eggs']['EX']['pokemon'][0]
        elif meetup:
            raidtype = 'egg'
            egglevel = 'EX'
            chsplit = name.split('-')
            del chsplit[0]
            raid_details = ' '.join(chsplit)
            raid_details = raid_details.strip()
            if (not topic):
                exp = raidmessage.created_at.replace(tzinfo=datetime.timezone.utc).timestamp() + (((60 * 60) * 24) * 14)
                manual_timer = False
            else:
                topicsplit = topic.split('|')
                localhatch = datetime.datetime.strptime(topicsplit[0][:(- 9)], 'Hatches on %B %d at %I:%M %p')
                utchatch = localhatch - datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])
                exp = utchatch.replace(year=now.year, tzinfo=datetime.timezone.utc).timestamp()
                manual_timer = True
            pokemon = ''
        else:
            await channel.send(_("I couldn't recognize this as a raid channel!"))
            return
        async for message in channel.history(limit=500):
            if message.author.id == guild.me.id:
                if (_('is interested') in message.content) or (_('on the way') in message.content) or (_('at the raid') in message.content) or (_('no longer') in message.content) or (_('left the raid') in message.content):
                    if message.raw_mentions:
                        if message.raw_mentions[0] not in trainer_dict:
                            trainerid = message.raw_mentions[0]
                            status = {'maybe':0, 'coming':0, 'here':0, 'lobby':0}
                            trainerstatus = None
                            if _('is interested') in message.content:
                                trainerstatus = 'maybe'
                            if _('on the way') in message.content:
                                trainerstatus = 'coming'
                            if _('at the raid') in message.content:
                                trainerstatus = 'here'
                            if (_('no longer') in message.content) or (_('left the raid') in message.content):
                                trainerstatus = None
                            if _('trainers') in message.content:
                                messagesplit = message.content.split()
                                if messagesplit[-1].isdigit():
                                    count = int(messagesplit[-13])
                                    party = {'mystic':int(messagesplit[-10]), 'valor':int(messagesplit[-7]), 'instinct':int(messagesplit[-4]), 'unknown':int(messagesplit[-1])}
                                else:
                                    count = 1
                                    party = {'mystic':0, 'valor':0, 'instinct':0, 'unknown':count}
                            else:
                                count = 1
                                user = ctx.guild.get_member(trainerid)
                                for role in user.roles:
                                    if role.name.lower() == 'mystic':
                                        party = {'mystic':1, 'valor':0, 'instinct':0, 'unknown':0}
                                        break
                                    elif role.name.lower() == 'valor':
                                        party = {'mystic':0, 'valor':1, 'instinct':0, 'unknown':0}
                                        break
                                    elif role.name.lower() == 'instinct':
                                        party = {'mystic':0, 'valor':0, 'instinct':1, 'unknown':0}
                                        break
                                    else:
                                        party = {'mystic':0, 'valor':0, 'instinct':0, 'unknown':1}
                            if trainerstatus:
                                status[trainerstatus] = count
                            trainer_dict[trainerid] = {
                                'status': status,
                                'count': count,
                                'party': party
                            }
                        else:
                            continue
                    else:
                        continue
        guild_dict[channel.guild.id]['raidchannel_dict'][channel.id] = {
            'reportcity': reportchannel,
            'trainer_dict': trainer_dict,
            'exp': exp,
            'manual_timer': manual_timer,
            'active': True,
            'raidmessage': raidmessage.id,
            'raidreport': None,
            'address': raid_details,
            'type': raidtype,
            'pokemon': pokemon,
            'egglevel': egglevel
        }
        await _edit_party(channel, message.author)
        recovermsg = _("This channel has been recovered! However, there may be some inaccuracies in what I remembered! Here's what I have:")
        bulletpoint = '🔹'
        recovermsg += ('\n' + bulletpoint) + (await _interest(ctx))
        recovermsg += ('\n' + bulletpoint) + (await _otw(ctx))
        recovermsg += ('\n' + bulletpoint) + (await _waiting(ctx))
        if (not manual_timer):
            if raidtype == 'egg':
                action = _('hatch')
                type = _('egg')
            elif raidtype == 'raid':
                action = _('end')
                type = _('raid')
            recovermsg += _("\nI'm not sure when this {raidtype} will {action}, so please use **!timerset** if you can!").format(raidtype=type, action=action)
        else:
            recovermsg += ('\n' + bulletpoint) + (await print_raid_timer(channel))
        await _edit_party(channel, ctx.message.author)
        await channel.send(recovermsg)
        event_loop.create_task(expiry_check(channel))

@Meowth.command()
@checks.activechannel()
async def duplicate(ctx):
    """A command to report a raid channel as a duplicate.

    Usage: !duplicate
    Works only in raid channels. When three users report a channel as a duplicate,
    Kyogre deactivates the channel and marks it for deletion."""
    channel = ctx.channel
    author = ctx.author
    guild = ctx.guild
    rc_d = guild_dict[guild.id]['raidchannel_dict'][channel.id]
    t_dict = rc_d['trainer_dict']
    can_manage = channel.permissions_for(author).manage_channels
    raidtype = _("event") if guild_dict[guild.id]['raidchannel_dict'][channel.id].get('meetup',False) else _("raid")
    if can_manage:
        dupecount = 2
        rc_d['duplicate'] = dupecount
    else:
        if author.id in t_dict:
            try:
                if t_dict[author.id]['dupereporter']:
                    dupeauthmsg = await channel.send(_("You've already made a duplicate report for this {raidtype}!").format(raidtype=raidtype))
                    await asyncio.sleep(10)
                    await dupeauthmsg.delete()
                    return
                else:
                    t_dict[author.id]['dupereporter'] = True
            except KeyError:
                t_dict[author.id]['dupereporter'] = True
        else:
            t_dict[author.id] = {
                'status': {'maybe':0, 'coming':0, 'here':0, 'lobby':0},
                'dupereporter': True,
            }
        try:
            dupecount = rc_d['duplicate']
        except KeyError:
            dupecount = 0
            rc_d['duplicate'] = dupecount
    dupecount += 1
    rc_d['duplicate'] = dupecount
    if dupecount >= 3:
        rusure = await channel.send(_('Are you sure you wish to remove this {raidtype}?').format(raidtype=raidtype))
        try:
            timeout = False
            res, reactuser = await ask(rusure, channel, author.id)
        except TypeError:
            timeout = True
        if not timeout:
            if res.emoji == '❎':
                await rusure.delete()
                confirmation = await channel.send(_('Duplicate Report cancelled.'))
                logger.info((('Duplicate Report - Cancelled - ' + channel.name) + ' - Report by ') + author.name)
                dupecount = 2
                guild_dict[guild.id]['raidchannel_dict'][channel.id]['duplicate'] = dupecount
                await asyncio.sleep(10)
                await confirmation.delete()
                return
            elif res.emoji == '✅':
                await rusure.delete()
                await channel.send(_('Duplicate Confirmed'))
                logger.info((('Duplicate Report - Channel Expired - ' + channel.name) + ' - Last Report by ') + author.name)
                raidmsg = await channel.get_message(rc_d['raidmessage'])
                reporter = raidmsg.mentions[0]
                if 'egg' in raidmsg.content:
                    egg_reports = guild_dict[guild.id]['trainers'][reporter.id]['egg_reports']
                    guild_dict[guild.id]['trainers'][reporter.id]['egg_reports'] = egg_reports - 1
                elif 'EX' in raidmsg.content:
                    ex_reports = guild_dict[guild.id]['trainers'][reporter.id]['ex_reports']
                    guild_dict[guild.id]['trainers'][reporter.id]['ex_reports'] = ex_reports - 1
                else:
                    raid_reports = guild_dict[guild.id]['trainers'][reporter.id]['raid_reports']
                    guild_dict[guild.id]['trainers'][reporter.id]['raid_reports'] = raid_reports - 1
                await expire_channel(channel)
                return
        else:
            await rusure.delete()
            confirmation = await channel.send(_('Duplicate Report Timed Out.'))
            logger.info((('Duplicate Report - Timeout - ' + channel.name) + ' - Report by ') + author.name)
            dupecount = 2
            guild_dict[guild.id]['raidchannel_dict'][channel.id]['duplicate'] = dupecount
            await asyncio.sleep(10)
            await confirmation.delete()
    else:
        rc_d['duplicate'] = dupecount
        confirmation = await channel.send(_('Duplicate report #{duplicate_report_count} received.').format(duplicate_report_count=str(dupecount)))
        logger.info((((('Duplicate Report - ' + channel.name) + ' - Report #') + str(dupecount)) + '- Report by ') + author.name)
        return

@Meowth.command()
async def counters(ctx, *, args=''):
    """Simulate a Raid battle with Pokebattler.

    Usage: !counters [pokemon] [weather] [user]
    See !help weather for acceptable values for weather.
    If [user] is a valid Pokebattler user id, Kyogre will simulate the Raid with that user's Pokebox.
    Uses current boss and weather by default if available.
    """
    rgx = '[^a-zA-Z0-9 ]'
    channel = ctx.channel
    guild = channel.guild
    user = guild_dict[ctx.guild.id].get('trainers',{}).get(ctx.author.id,{}).get('pokebattlerid', None)
    if checks.check_raidchannel(ctx) and not checks.check_meetupchannel(ctx):
        if args:
            args_split = args.split()
            for arg in args_split:
                if arg.isdigit():
                    user = arg
                    break
        try:
            ctrsmessage = await channel.get_message(guild_dict[guild.id]['raidchannel_dict'][channel.id].get('ctrsmessage',None))
        except (discord.errors.NotFound, discord.errors.Forbidden, discord.errors.HTTPException):
            pass
        pkmn = guild_dict[guild.id]['raidchannel_dict'][channel.id].get('pokemon', None)
        if pkmn:
            if not user:
                try:
                    ctrsmessage = await channel.get_message(guild_dict[guild.id]['raidchannel_dict'][channel.id].get('ctrsmessage',None))
                    ctrsembed = ctrsmessage.embeds[0]
                    ctrsembed.remove_field(6)
                    ctrsembed.remove_field(6)
                    await channel.send(content=ctrsmessage.content,embed=ctrsembed)
                    return
                except (discord.errors.NotFound, discord.errors.Forbidden, discord.errors.HTTPException):
                    pass
            moveset = guild_dict[guild.id]['raidchannel_dict'][channel.id].get('moveset', 0)
            movesetstr = guild_dict[guild.id]['raidchannel_dict'][channel.id]['ctrs_dict'].get(moveset,{}).get('moveset',"Unknown Moveset")
            weather = guild_dict[guild.id]['raidchannel_dict'][channel.id].get('weather', None)
        else:
            pkmn = next((str(p) for p in get_raidlist() if not str(p).isdigit() and re.sub(rgx, '', str(p)) in re.sub(rgx, '', args.lower())), None)
            if not pkmn:
                await ctx.channel.send(_("You're missing some details! Be sure to enter a pokemon that appears in raids! Usage: **!counters <pkmn> [weather] [user ID]**"))
                return
        if not weather:
            if args:
                weather_list = [_('none'), _('extreme'), _('clear'), _('sunny'), _('rainy'),
                                _('partlycloudy'), _('cloudy'), _('windy'), _('snow'), _('fog')]
                weather = next((w for w in weather_list if re.sub(rgx, '', w) in re.sub(rgx, '', args.lower())), None)
        pkmn = Pokemon.get_pokemon(Meowth, pkmn)
        return await _counters(ctx, pkmn, user, weather, movesetstr)
    if args:
        args_split = args.split()
        for arg in args_split:
            if arg.isdigit():
                user = arg
                break
        rgx = '[^a-zA-Z0-9]'
        pkmn = next((str(p) for p in get_raidlist() if not str(p).isdigit() and re.sub(rgx, '', str(p)) in re.sub(rgx, '', args.lower())), None)
        if not pkmn:
            pkmn = guild_dict[guild.id]['raidchannel_dict'].get(channel.id,{}).get('pokemon', None)
        weather_list = [_('none'), _('extreme'), _('clear'), _('sunny'), _('rainy'),
                        _('partlycloudy'), _('cloudy'), _('windy'), _('snow'), _('fog')]
        weather = next((w for w in weather_list if re.sub(rgx, '', w) in re.sub(rgx, '', args.lower())), None)
        if not weather:
            weather = guild_dict[guild.id]['raidchannel_dict'].get(channel.id,{}).get('weather', None)
    else:
        pkmn = guild_dict[guild.id]['raidchannel_dict'].get(channel.id,{}).get('pokemon', None)
        weather = guild_dict[guild.id]['raidchannel_dict'].get(channel.id,{}).get('weather', None)
    if not pkmn:
        await ctx.channel.send(_("You're missing some details! Be sure to enter a pokemon that appears in raids! Usage: **!counters <pkmn> [weather] [user ID]**"))
        return
    pkmn = Pokemon.get_pokemon(Meowth, pkmn)
    await _counters(ctx, pkmn, user, weather, "Unknown Moveset")

async def _counters(ctx, pkmn, user = None, weather = None, movesetstr = "Unknown Moveset"):
    if isinstance(pkmn, str):
        pkmn = Pokemon.get_pokemon(Meowth, pkmn)
    if not pkmn:
        return
    img_url = pkmn.img_url
    level = pkmn.raid_level
    if not level.isdigit():
        level = "5"
    pokebattler_name = pkmn.species.upper()
    if pkmn.alolan:
        pokebattler_name += "_ALOLA_FORM"
    url = "https://fight.pokebattler.com/raids/defenders/{pkmn}/levels/RAID_LEVEL_{level}/attackers/".format(pkmn=pokebattler_name,level=level)
    if user:
        url += "users/{user}/".format(user=user)
        userstr = _("user #{user}'s").format(user=user)
    else:
        url += "levels/30/"
        userstr = _("Level 30")
    weather_list = [_('none'), _('extreme'), _('clear'), _('sunny'), _('rainy'),
                    _('partlycloudy'), _('cloudy'), _('windy'), _('snow'), _('fog')]
    match_list = ['NO_WEATHER','NO_WEATHER','CLEAR','CLEAR','RAINY',
                        'PARTLY_CLOUDY','OVERCAST','WINDY','SNOW','FOG']
    if not weather:
        index = 0
    else:
        index = weather_list.index(weather)
    weather = match_list[index]
    url += "strategies/CINEMATIC_ATTACK_WHEN_POSSIBLE/DEFENSE_RANDOM_MC?sort=OVERALL&"
    url += "weatherCondition={weather}&dodgeStrategy=DODGE_REACTION_TIME&aggregation=AVERAGE".format(weather=weather)
    async with ctx.typing():
        async with aiohttp.ClientSession() as sess:
            async with sess.get(url) as resp:
                data = await resp.json()
        title_url = url.replace('https://fight', 'https://www')
        colour = ctx.guild.me.colour
        hyperlink_icon = 'https://i.imgur.com/fn9E5nb.png'
        pbtlr_icon = 'https://www.pokebattler.com/favicon-32x32.png'
        data = data['attackers'][0]
        raid_cp = data['cp']
        atk_levels = '30'
        if movesetstr == "Unknown Moveset":
            ctrs = data['randomMove']['defenders'][-6:]
            est = data['randomMove']['total']['estimator']
        else:
            for moveset in data['byMove']:
                move1 = moveset['move1'][:-5].lower().title().replace('_', ' ')
                move2 = moveset['move2'].lower().title().replace('_', ' ')
                moveset_str = f'{move1} | {move2}'
                if moveset_str == movesetstr:
                    ctrs = moveset['defenders'][-6:]
                    est = moveset['total']['estimator']
                    break
            else:
                movesetstr = "Unknown Moveset"
                ctrs = data['randomMove']['defenders'][-6:]
                est = data['randomMove']['total']['estimator']
        def clean(txt):
            return txt.replace('_', ' ').title()
        title = _('{pkmn} | {weather} | {movesetstr}').format(pkmn=pkmn.name,weather=weather_list[index].title(),movesetstr=movesetstr)
        stats_msg = _("**CP:** {raid_cp}\n").format(raid_cp=raid_cp)
        stats_msg += _("**Weather:** {weather}\n").format(weather=clean(weather))
        stats_msg += _("**Attacker Level:** {atk_levels}").format(atk_levels=atk_levels)
        ctrs_embed = discord.Embed(colour=colour)
        ctrs_embed.set_author(name=title,url=title_url,icon_url=hyperlink_icon)
        ctrs_embed.set_thumbnail(url=img_url)
        ctrs_embed.set_footer(text=_('Results courtesy of Pokebattler'), icon_url=pbtlr_icon)
        index = 1
        for ctr in reversed(ctrs):
            ctr_name = clean(ctr['pokemonId'])
            ctr_nick = clean(ctr.get('name',''))
            ctr_cp = ctr['cp']
            moveset = ctr['byMove'][-1]
            moves = _("{move1} | {move2}").format(move1=clean(moveset['move1'])[:-5], move2=clean(moveset['move2']))
            name = _("#{index} - {ctr_name}").format(index=index, ctr_name=(ctr_nick or ctr_name))
            cpstr = _("CP")
            ctrs_embed.add_field(name=name,value=f"{cpstr}: {ctr_cp}\n{moves}")
            index += 1
        ctrs_embed.add_field(name=_("Results with {userstr} attackers").format(userstr=userstr), value=_("[See your personalized results!](https://www.pokebattler.com/raids/{pkmn})").format(pkmn=pokebattler_name))
        if user:
            ctrs_embed.add_field(name=_("Pokebattler Estimator:"), value=_("Difficulty rating: {est}").format(est=est))
            await ctx.author.send(embed=ctrs_embed)
            return
        await ctx.channel.send(embed=ctrs_embed)

async def _get_generic_counters(guild, pkmn, weather=None):
    if isinstance(pkmn, str):
        pkmn = Pokemon.get_pokemon(Meowth, pkmn)
    if not pkmn:
        return
    emoji_dict = {0: '0\u20e3', 1: '1\u20e3', 2: '2\u20e3', 3: '3\u20e3', 4: '4\u20e3', 5: '5\u20e3', 6: '6\u20e3', 7: '7\u20e3', 8: '8\u20e3', 9: '9\u20e3', 10: '10\u20e3'}
    ctrs_dict = {}
    ctrs_index = 0
    ctrs_dict[ctrs_index] = {}
    ctrs_dict[ctrs_index]['moveset'] = "Unknown Moveset"
    ctrs_dict[ctrs_index]['emoji'] = '0\u20e3'
    img_url = pkmn.img_url
    level = pkmn.raid_level
    if not level.isdigit():
        level = "5"
    pokebattler_name = pkmn.species.upper()
    if pkmn.alolan:
        pokebattler_name = f"{pkmn.species.upper()}_ALOLA_FORM"
    url = "https://fight.pokebattler.com/raids/defenders/{pkmn}/levels/RAID_LEVEL_{level}/attackers/".format(pkmn=pokebattler_name,level=level)
    url += "levels/30/"
    weather_list = [_('none'), _('extreme'), _('clear'), _('sunny'), _('rainy'),
                    _('partlycloudy'), _('cloudy'), _('windy'), _('snow'), _('fog')]
    match_list = ['NO_WEATHER','NO_WEATHER','CLEAR','CLEAR','RAINY',
                        'PARTLY_CLOUDY','OVERCAST','WINDY','SNOW','FOG']
    if not weather:
        index = 0
    else:
        index = weather_list.index(weather)
    weather = match_list[index]
    url += "strategies/CINEMATIC_ATTACK_WHEN_POSSIBLE/DEFENSE_RANDOM_MC?sort=OVERALL&"
    url += "weatherCondition={weather}&dodgeStrategy=DODGE_REACTION_TIME&aggregation=AVERAGE".format(weather=weather)
    title_url = url.replace('https://fight', 'https://www')
    hyperlink_icon = 'https://i.imgur.com/fn9E5nb.png'
    pbtlr_icon = 'https://www.pokebattler.com/favicon-32x32.png'
    async with aiohttp.ClientSession() as sess:
        async with sess.get(url) as resp:
            data = await resp.json()
    data = data['attackers'][0]
    raid_cp = data['cp']
    atk_levels = '30'
    ctrs = data['randomMove']['defenders'][-6:]
    def clean(txt):
        return txt.replace('_', ' ').title()
    title = _('{pkmn} | {weather} | Unknown Moveset').format(pkmn=pkmn.name,weather=weather_list[index].title())
    stats_msg = _("**CP:** {raid_cp}\n").format(raid_cp=raid_cp)
    stats_msg += _("**Weather:** {weather}\n").format(weather=clean(weather))
    stats_msg += _("**Attacker Level:** {atk_levels}").format(atk_levels=atk_levels)
    ctrs_embed = discord.Embed(colour=guild.me.colour)
    ctrs_embed.set_author(name=title,url=title_url,icon_url=hyperlink_icon)
    ctrs_embed.set_thumbnail(url=img_url)
    ctrs_embed.set_footer(text=_('Results courtesy of Pokebattler'), icon_url=pbtlr_icon)
    ctrindex = 1
    for ctr in reversed(ctrs):
        ctr_name = clean(ctr['pokemonId'])
        moveset = ctr['byMove'][-1]
        moves = _("{move1} | {move2}").format(move1=clean(moveset['move1'])[:-5], move2=clean(moveset['move2']))
        name = _("#{index} - {ctr_name}").format(index=ctrindex, ctr_name=ctr_name)
        ctrs_embed.add_field(name=name,value=moves)
        ctrindex += 1
    ctrs_dict[ctrs_index]['embed'] = ctrs_embed
    for moveset in data['byMove']:
        ctrs_index += 1
        move1 = moveset['move1'][:-5].lower().title().replace('_', ' ')
        move2 = moveset['move2'].lower().title().replace('_', ' ')
        movesetstr = f'{move1} | {move2}'
        ctrs = moveset['defenders'][-6:]
        title = _('{pkmn} | {weather} | {movesetstr}').format(pkmn=pkmn.name, weather=weather_list[index].title(), movesetstr=movesetstr)
        ctrs_embed = discord.Embed(colour=guild.me.colour)
        ctrs_embed.set_author(name=title,url=title_url,icon_url=hyperlink_icon)
        ctrs_embed.set_thumbnail(url=img_url)
        ctrs_embed.set_footer(text=_('Results courtesy of Pokebattler'), icon_url=pbtlr_icon)
        ctrindex = 1
        for ctr in reversed(ctrs):
            ctr_name = clean(ctr['pokemonId'])
            moveset = ctr['byMove'][-1]
            moves = _("{move1} | {move2}").format(move1=clean(moveset['move1'])[:-5], move2=clean(moveset['move2']))
            name = _("#{index} - {ctr_name}").format(index=ctrindex, ctr_name=ctr_name)
            ctrs_embed.add_field(name=name,value=moves)
            ctrindex += 1
        ctrs_dict[ctrs_index] = {'moveset': movesetstr, 'embed': ctrs_embed, 'emoji': emoji_dict[ctrs_index]}
    moveset_list = []
    for moveset in ctrs_dict:
        moveset_list.append(f"{ctrs_dict[moveset]['emoji']}: {ctrs_dict[moveset]['moveset']}\n")
    for moveset in ctrs_dict:
        ctrs_split = int(round(len(moveset_list)/2+0.1))
        ctrs_dict[moveset]['embed'].add_field(name=_("**Possible Movesets:**"), value=f"{''.join(moveset_list[:ctrs_split])}", inline=True)
        ctrs_dict[moveset]['embed'].add_field(name="\u200b", value=f"{''.join(moveset_list[ctrs_split:])}",inline=True)
        ctrs_dict[moveset]['embed'].add_field(name=_("Results with Level 30 attackers"), value=_("[See your personalized results!](https://www.pokebattler.com/raids/{pkmn})").format(pkmn=pokebattler_name),inline=False)

    return ctrs_dict

@Meowth.command()
@checks.activechannel()
async def weather(ctx, *, weather):
    """Sets the weather for the raid.
    Usage: !weather <weather>
    Only usable in raid channels.
    Acceptable options: none, extreme, clear, rainy, partlycloudy, cloudy, windy, snow, fog"""
    weather_list = [_('none'), _('extreme'), _('clear'), _('sunny'), _('rainy'),
                    _('partlycloudy'), _('cloudy'), _('windy'), _('snow'), _('fog')]
    if weather.lower() not in weather_list:
        return await ctx.channel.send(_("Enter one of the following weather conditions: {}").format(", ".join(weather_list)))
    else:
        guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['weather'] = weather.lower()
        pkmn = guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id].get('pokemon', None)
        pkmn = Pokemon.get_pokemon(Meowth, pkmn)
        if pkmn:
            if str(pkmn.raid_level) in guild_dict[ctx.guild.id]['configure_dict']['counters']['auto_levels']:
                ctrs_dict = await _get_generic_counters(ctx.guild, pkmn, weather.lower())
                try:
                    ctrsmessage = await ctx.channel.get_message(guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['ctrsmessage'])
                    moveset = guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['moveset']
                    newembed = ctrs_dict[moveset]['embed']
                    await ctrsmessage.edit(embed=newembed)
                except (discord.errors.NotFound, discord.errors.Forbidden, discord.errors.HTTPException):
                    pass
                guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['ctrs_dict'] = ctrs_dict
        return await ctx.channel.send(_("Weather set to {}!").format(weather.lower()))

"""
Status Management
"""

status_parse_rgx = r'^(\d+)$|^(\d+(?:[, ]+))?([\dimvu ,]+)?(?:[, ]*)([a-zA-Z ,]+)?$'
status_parser = re.compile(status_parse_rgx)

async def _parse_teamcounts(ctx, teamcounts, trainer_dict, egglevel):
    if (not teamcounts):
        if ctx.author.id in trainer_dict:
            bluecount = str(trainer_dict[ctx.author.id]['party']['mystic']) + 'm '
            redcount = str(trainer_dict[ctx.author.id]['party']['valor']) + 'v '
            yellowcount = str(trainer_dict[ctx.author.id]['party']['instinct']) + 'i '
            unknowncount = str(trainer_dict[ctx.author.id]['party']['unknown']) + 'u '
            teamcounts = ((((str(trainer_dict[ctx.author.id]['count']) + ' ') + bluecount) + redcount) + yellowcount) + unknowncount
        else:
            teamcounts = '1'
    if "all" in teamcounts.lower():
        teamcounts = "{teamcounts} {bosslist}".format(teamcounts=teamcounts,bosslist=",".join([s.title() for s in raid_info['raid_eggs'][egglevel]['pokemon']]))
        teamcounts = teamcounts.lower().replace("all","").strip()
    return status_parser.fullmatch(teamcounts)

async def _process_status_command(ctx, teamcounts):
    trainer_dict = guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['trainer_dict']
    entered_interest = trainer_dict.get(ctx.author.id, {}).get('interest', [])
    egglevel = guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['egglevel']
    parsed_counts = await _parse_teamcounts(ctx, teamcounts, trainer_dict, egglevel)
    errors = []
    if not parsed_counts:
        raise ValueError("I couldn't understand that format! Check the format against `!help interested` and try again.")
    totalA, totalB, groups, bosses = parsed_counts.groups()
    total = totalA or totalB
    if bosses and guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['type'] == "egg":
        entered_interest = set(entered_interest)
        bosses_list = bosses.lower().split(',')
        if isinstance(bosses_list, str):
            bosses_list = [bosses.lower()]
        for boss in bosses_list:
            pkmn = Pokemon.get_pokemon(Meowth, boss)
            if pkmn:
                name = pkmn.name.lower()
                if name in raid_info['raid_eggs'][egglevel]['pokemon']:
                    entered_interest.add(name)
                else:
                    errors.append(_("{pkmn} doesn't appear in level {egglevel} raids! Please try again.").format(pkmn=pkmn.name,egglevel=egglevel))
        if errors:
            errors.append(_("Invalid Pokemon detected. Please check the pinned message for the list of possible bosses and try again."))
            raise ValueError('\n'.join(errors))
    elif not bosses and guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['type'] == 'egg':
        entered_interest = [p for p in raid_info['raid_eggs'][egglevel]['pokemon']]
    if total:
        total = int(total)
    elif (ctx.author.id in trainer_dict) and (sum(trainer_dict[ctx.author.id]['status'].values()) > 0):
        total = trainer_dict[ctx.author.id]['count']
    elif groups:
        total = re.sub('[^0-9 ]', ' ', groups)
        total = sum([int(x) for x in total.split()])
    else:
        total = 1
    if not groups:
        groups = ''
    teamcounts = f"{total} {groups}"
    result = await _party_status(ctx, total, teamcounts)
    return (result, entered_interest)

@Meowth.command(aliases=['i', 'maybe'])
@checks.activechannel()
async def interested(ctx, *, teamcounts: str=None):
    """Indicate you are interested in the raid.

    Usage: !interested [count] [party] [bosses]
    Works only in raid channels. If count is omitted, assumes you are a group of 1.
    Otherwise, this command expects at least one word in your message to be a number,
    and will assume you are a group with that many people.

    Party is also optional. Format is #m #v #i #u to tell your party's teams."""
    try:
        result, entered_interest = await _process_status_command(ctx, teamcounts)
    except ValueError as e:
        return await ctx.channel.send(e)
    if isinstance(result, list):
        count = result[0]
        partylist = result[1]
        await _maybe(ctx.channel, ctx.author, count, partylist, entered_interest)

async def _maybe(channel, author, count, party, entered_interest=None):
    trainer_dict = guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['trainer_dict']
    allblue = 0
    allred = 0
    allyellow = 0
    allunknown = 0
    if (not party):
        for role in author.roles:
            if role.name.lower() == 'mystic':
                allblue = count
                break
            elif role.name.lower() == 'valor':
                allred = count
                break
            elif role.name.lower() == 'instinct':
                allyellow = count
                break
        else:
            allunknown = count
        party = {'mystic':allblue, 'valor':allred, 'instinct':allyellow, 'unknown':allunknown}
    if count == 1:
        team_emoji = max(party, key=lambda key: party[key])
        if team_emoji == "unknown":
            team_emoji = "❔"
        else:
            team_emoji = parse_emoji(channel.guild, config['team_dict'][team_emoji])
        await channel.send(_('{member} is interested! {emoji}: 1').format(member=author.mention, emoji=team_emoji))
    else:
        msg = _('{member} is interested with a total of {trainer_count} trainers!').format(member=author.mention, trainer_count=count)
        await channel.send('{msg} {blue_emoji}: {mystic} | {red_emoji}: {valor} | {yellow_emoji}: {instinct} | ❔: {unknown}'.format(msg=msg, blue_emoji=parse_emoji(channel.guild, config['team_dict']['mystic']), mystic=party['mystic'], red_emoji=parse_emoji(channel.guild, config['team_dict']['valor']), valor=party['valor'], instinct=party['instinct'], yellow_emoji=parse_emoji(channel.guild, config['team_dict']['instinct']), unknown=party['unknown']))
    if author.id not in guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['trainer_dict']:
        trainer_dict[author.id] = {}
    trainer_dict[author.id]['status'] = {'maybe':count, 'coming':0, 'here':0, 'lobby':0}
    if entered_interest:
        trainer_dict[author.id]['interest'] = list(entered_interest)
    trainer_dict[author.id]['count'] = count
    trainer_dict[author.id]['party'] = party
    await _edit_party(channel, author)
    guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['trainer_dict'] = trainer_dict
    regions = guild_dict[channel.guild.id]['raidchannel_dict'][channel.id].get('regions', None)
    if regions:
        await _update_listing_channels(channel.guild, 'raid', edit=True, regions=regions)

@Meowth.command(aliases=['c'])
@checks.activechannel()
async def coming(ctx, *, teamcounts: str=None):
    """Indicate you are on the way to a raid.

    Usage: !coming [count] [party]
    Works only in raid channels. If count is omitted, checks for previous !maybe
    command and takes the count from that. If it finds none, assumes you are a group
    of 1.
    Otherwise, this command expects at least one word in your message to be a number,
    and will assume you are a group with that many people.

    Party is also optional. Format is #m #v #i #u to tell your party's teams."""
    try:
        result, entered_interest = await _process_status_command(ctx, teamcounts)
    except ValueError as e:
        return await ctx.channel.send(e)
    if isinstance(result, list):
        count = result[0]
        partylist = result[1]
        await _coming(ctx.channel, ctx.author, count, partylist, entered_interest)

async def _coming(channel, author, count, party, entered_interest=None):
    allblue = 0
    allred = 0
    allyellow = 0
    allunknown = 0
    trainer_dict = guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['trainer_dict']
    if (not party):
        for role in author.roles:
            if role.name.lower() == 'mystic':
                allblue = count
                break
            elif role.name.lower() == 'valor':
                allred = count
                break
            elif role.name.lower() == 'instinct':
                allyellow = count
                break
        else:
            allunknown = count
        party = {'mystic':allblue, 'valor':allred, 'instinct':allyellow, 'unknown':allunknown}
    if count == 1:
        team_emoji = max(party, key=lambda key: party[key])
        if team_emoji == "unknown":
            team_emoji = "❔"
        else:
            team_emoji = parse_emoji(channel.guild, config['team_dict'][team_emoji])
        await channel.send(_('{member} is on the way! {emoji}: 1').format(member=author.mention, emoji=team_emoji))
    else:
        msg = _('{member} is on the way with a total of {trainer_count} trainers!').format(member=author.mention, trainer_count=count)
        await channel.send('{msg} {blue_emoji}: {mystic} | {red_emoji}: {valor} | {yellow_emoji}: {instinct} | ❔: {unknown}'.format(msg=msg, blue_emoji=parse_emoji(channel.guild, config['team_dict']['mystic']), mystic=party['mystic'], red_emoji=parse_emoji(channel.guild, config['team_dict']['valor']), valor=party['valor'], instinct=party['instinct'], yellow_emoji=parse_emoji(channel.guild, config['team_dict']['instinct']), unknown=party['unknown']))
    if author.id not in trainer_dict:
        trainer_dict[author.id] = {

        }
    trainer_dict[author.id]['status'] = {'maybe':0, 'coming':count, 'here':0, 'lobby':0}
    trainer_dict[author.id]['count'] = count
    trainer_dict[author.id]['party'] = party
    if entered_interest:
        trainer_dict[author.id]['interest'] = entered_interest
    await _edit_party(channel, author)
    guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['trainer_dict'] = trainer_dict
    regions = guild_dict[channel.guild.id]['raidchannel_dict'][channel.id].get('regions', None)
    if regions:
        await _update_listing_channels(channel.guild, 'raid', edit=True, regions=regions)

@Meowth.command(aliases=['h'])
@checks.activechannel()
async def here(ctx, *, teamcounts: str=None):
    """Indicate you have arrived at the raid.

    Usage: !here [count] [party]
    Works only in raid channels. If message is omitted, and
    you have previously issued !coming, then preserves the count
    from that command. Otherwise, assumes you are a group of 1.
    Otherwise, this command expects at least one word in your message to be a number,
    and will assume you are a group with that many people.

    Party is also optional. Format is #m #v #i #u to tell your party's teams."""
    try:
        result, entered_interest = await _process_status_command(ctx, teamcounts)
    except ValueError as e:
        return await ctx.channel.send(e)
    if isinstance(result, list):
        count = result[0]
        partylist = result[1]
        await _here(ctx.channel, ctx.author, count, partylist, entered_interest)

async def _here(channel, author, count, party, entered_interest=None):
    lobbymsg = ''
    allblue = 0
    allred = 0
    allyellow = 0
    allunknown = 0
    trainer_dict = guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['trainer_dict']
    raidtype = _("event") if guild_dict[channel.guild.id]['raidchannel_dict'][channel.id].get('meetup',False) else _("raid")
    try:
        if guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['lobby']:
            lobbymsg += _('\nThere is a group already in the lobby! Use **!lobby** to join them or **!backout** to request a backout! Otherwise, you may have to wait for the next group!')
    except KeyError:
        pass
    if (not party):
        for role in author.roles:
            if role.name.lower() == 'mystic':
                allblue = count
                break
            elif role.name.lower() == 'valor':
                allred = count
                break
            elif role.name.lower() == 'instinct':
                allyellow = count
                break
        else:
            allunknown = count
        party = {'mystic':allblue, 'valor':allred, 'instinct':allyellow, 'unknown':allunknown}
    if count == 1:
        team_emoji = max(party, key=lambda key: party[key])
        if team_emoji == "unknown":
            team_emoji = "❔"
        else:
            team_emoji = parse_emoji(channel.guild, config['team_dict'][team_emoji])
        msg = _('{member} is at the {raidtype}! {emoji}: 1').format(member=author.mention, emoji=team_emoji, raidtype=raidtype)
        await channel.send(msg + lobbymsg)
    else:
        msg = _('{member} is at the {raidtype} with a total of {trainer_count} trainers!').format(member=author.mention, trainer_count=count, raidtype=raidtype)
        msg += ' {blue_emoji}: {mystic} | {red_emoji}: {valor} | {yellow_emoji}: {instinct} | ❔: {unknown}'.format(blue_emoji=parse_emoji(channel.guild, config['team_dict']['mystic']), mystic=party['mystic'], red_emoji=parse_emoji(channel.guild, config['team_dict']['valor']), valor=party['valor'], instinct=party['instinct'], yellow_emoji=parse_emoji(channel.guild, config['team_dict']['instinct']), unknown=party['unknown'])
        await channel.send(msg + lobbymsg)
    if author.id not in trainer_dict:
        trainer_dict[author.id] = {

        }
    trainer_dict[author.id]['status'] = {'maybe':0, 'coming':0, 'here':count, 'lobby':0}
    trainer_dict[author.id]['count'] = count
    trainer_dict[author.id]['party'] = party
    if entered_interest:
        trainer_dict[author.id]['interest'] = entered_interest
    await _edit_party(channel, author)
    guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['trainer_dict'] = trainer_dict
    regions = guild_dict[channel.guild.id]['raidchannel_dict'][channel.id].get('regions', None)
    if regions:
        await _update_listing_channels(channel.guild, 'raid', edit=True, regions=regions)

async def _party_status(ctx, total, teamcounts):
    channel = ctx.channel
    author = ctx.author
    trainer_dict = guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['trainer_dict'].get(author.id, {})
    roles = [r.name.lower() for r in author.roles]
    if 'mystic' in roles:
        my_team = 'mystic'
    elif 'valor' in roles:
        my_team = 'valor'
    elif 'instinct' in roles:
        my_team = 'instinct'
    else:
        my_team = 'unknown'
    if not teamcounts:
        teamcounts = "1"
    teamcounts = teamcounts.lower().split()
    if total and teamcounts[0].isdigit():
        del teamcounts[0]
    mystic = ['mystic', 0]
    instinct = ['instinct', 0]
    valor = ['valor', 0]
    unknown = ['unknown', 0]
    team_aliases = {
        'mystic': mystic,
        'blue': mystic,
        'm': mystic,
        'b': mystic,
        'instinct': instinct,
        'yellow': instinct,
        'i': instinct,
        'y': instinct,
        'valor': valor,
        'red': valor,
        'v': valor,
        'r': valor,
        'unknown': unknown,
        'grey': unknown,
        'gray': unknown,
        'u': unknown,
        'g': unknown,
    }
    if not teamcounts and total >= trainer_dict.get('count', 0):
        trainer_party = trainer_dict.get('party', {})
        for team in trainer_party:
            team_aliases[team][1] += trainer_party[team]
    regx = re.compile('([a-zA-Z]+)([0-9]+)|([0-9]+)([a-zA-Z]+)')
    for count in teamcounts:
        if count.isdigit():
            if total:
                return await channel.send(_('Only one non-team count can be accepted.'))
            else:
                total = int(count)
        else:
            match = regx.match(count)
            if match:
                match = regx.match(count).groups()
                str_match = match[0] or match[3]
                int_match = match[1] or match[2]
                if str_match in team_aliases.keys():
                    if int_match:
                        if team_aliases[str_match][1]:
                            return await channel.send(_('Only one count per team accepted.'))
                        else:
                            team_aliases[str_match][1] = int(int_match)
                            continue
            return await channel.send(_('Invalid format, please check and try again.'))
    team_total = ((mystic[1] + instinct[1]) + valor[1]) + unknown[1]
    if total:
        if int(team_total) > int(total):
            a = _('Team counts are higher than the total, double check your counts and try again. You entered **')
            b = _('** total and **')
            c = _('** in your party.')
            return await channel.send(((( a + str(total)) + b) + str(team_total)) + c)
        if int(total) > int(team_total):
            if team_aliases[my_team][1]:
                if unknown[1]:
                    return await channel.send(_('Something is not adding up! Try making sure your total matches what each team adds up to!'))
                unknown[1] = total - team_total
            else:
                team_aliases[my_team][1] = total - team_total
    partylist = {'mystic':mystic[1], 'valor':valor[1], 'instinct':instinct[1], 'unknown':unknown[1]}
    result = [total, partylist]
    return result

async def _edit_party(channel, author=None):
    egglevel = guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['egglevel']
    if egglevel != "0":
        boss_dict = {}
        boss_list = []
        display_list = []
        for entry in raid_info['raid_eggs'][egglevel]['pokemon']:
            p = Pokemon.get_pokemon(Meowth, entry)
            boss_list.append(p)
            boss_dict[p.name] = {"type": types_to_str(channel.guild, p.types), "total": 0}
    channel_dict = {"mystic":0,"valor":0,"instinct":0,"unknown":0,"maybe":0,"coming":0,"here":0,"total":0,"boss":0}
    team_list = ["mystic","valor","instinct","unknown"]
    status_list = ["maybe","coming","here"]
    trainer_dict = copy.deepcopy(guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['trainer_dict'])
    for trainer in trainer_dict:
        for team in team_list:
            channel_dict[team] += int(trainer_dict[trainer]['party'][team])
        for status in status_list:
            if trainer_dict[trainer]['status'][status]:
                channel_dict[status] += int(trainer_dict[trainer]['count'])
        if egglevel != "0":
            for boss in boss_list:
                if boss.name.lower() in trainer_dict[trainer].get('interest',[]):
                    boss_dict[boss.name]['total'] += int(trainer_dict[trainer]['count'])
                    channel_dict["boss"] += int(trainer_dict[trainer]['count'])
    if egglevel != "0":
        for boss in boss_list:
            if boss_dict[boss.name]['total'] > 0:
                bossstr = "{name} ({number}) {types} : **{count}**".format(name=boss.name,number=boss.id,types=boss_dict[boss.name]['type'],count=boss_dict[boss.name]['total'])
                display_list.append(bossstr)
            elif boss_dict[boss.name]['total'] == 0:
                bossstr = "{name} ({number}) {types}".format(name=boss.name,number=boss.id,types=boss_dict[boss.name]['type'])
                display_list.append(bossstr)
    channel_dict["total"] = channel_dict["maybe"] + channel_dict["coming"] + channel_dict["here"]
    reportchannel = Meowth.get_channel(guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['reportcity'])
    try:
        reportmsg = await reportchannel.get_message(guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['raidreport'])
    except:
        pass
    try:
        raidmsg = await channel.get_message(guild_dict[channel.guild.id]['raidchannel_dict'][channel.id]['raidmessage'])
    except:
        async for message in channel.history(limit=500, reverse=True):
            if author and message.author.id == channel.guild.me.id:
                c = _('Coordinate here')
                if c in message.content:
                    reportchannel = message.raw_channel_mentions[0]
                    raidmsg = message
                    break
    reportembed = raidmsg.embeds[0]
    newembed = discord.Embed(title=reportembed.title, url=reportembed.url, colour=channel.guild.me.colour)
    for field in reportembed.fields:
        t = _('team')
        s = _('status')
        if (t not in field.name.lower()) and (s not in field.name.lower()):
            newembed.add_field(name=field.name, value=field.value, inline=field.inline)
    if egglevel != "0" and not guild_dict[channel.guild.id].get('raidchannel_dict',{}).get(channel.id,{}).get('meetup',{}):
        if len(boss_list) > 1:
            newembed.set_field_at(0, name=_("**Boss Interest:**") if channel_dict["boss"] > 0 else _("**Possible Bosses:**"), value=_('{bosslist1}').format(bosslist1='\n'.join(display_list[::2])), inline=True)
            newembed.set_field_at(1, name='\u200b', value=_('{bosslist2}').format(bosslist2='\n'.join(display_list[1::2])), inline=True)
        else:
            newembed.set_field_at(0, name=_("**Boss Interest:**") if channel_dict["boss"] > 0 else _("**Possible Bosses:**"), value=_('{bosslist}').format(bosslist=''.join(display_list)), inline=True)
            newembed.set_field_at(1, name='\u200b', value='\u200b', inline=True)
    if channel_dict["total"] > 0:
        newembed.add_field(name=_('**Status List**'), value=_('Maybe: **{channelmaybe}** | Coming: **{channelcoming}** | Here: **{channelhere}**').format(channelmaybe=channel_dict["maybe"], channelcoming=channel_dict["coming"], channelhere=channel_dict["here"]), inline=True)
        newembed.add_field(name=_('**Team List**'), value='{blue_emoji}: **{channelblue}** | {red_emoji}: **{channelred}** | {yellow_emoji}: **{channelyellow}** | ❔: **{channelunknown}**'.format(blue_emoji=parse_emoji(channel.guild, config['team_dict']['mystic']), channelblue=channel_dict["mystic"], red_emoji=parse_emoji(channel.guild, config['team_dict']['valor']), channelred=channel_dict["valor"], yellow_emoji=parse_emoji(channel.guild, config['team_dict']['instinct']), channelyellow=channel_dict["instinct"], channelunknown=channel_dict["unknown"]), inline=True)
    newembed.set_footer(text=reportembed.footer.text, icon_url=reportembed.footer.icon_url)
    newembed.set_thumbnail(url=reportembed.thumbnail.url)
    try:
        await reportmsg.edit(embed=newembed)
    except:
        pass
    try:
        await raidmsg.edit(embed=newembed)
    except:
        pass

@Meowth.command(aliases=['l'])
@checks.activeraidchannel()
async def lobby(ctx, *, count: str=None):
    """Indicate you are entering the raid lobby.

    Usage: !lobby [message]
    Works only in raid channels. If message is omitted, and
    you have previously issued !coming, then preserves the count
    from that command. Otherwise, assumes you are a group of 1.
    Otherwise, this command expects at least one word in your message to be a number,
    and will assume you are a group with that many people."""
    try:
        if guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['type'] == 'egg':
            if guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['pokemon'] == '':
                await ctx.channel.send(_("Please wait until the raid egg has hatched before announcing you're coming or present."))
                return
    except:
        pass
    trainer_dict = guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['trainer_dict']
    if count:
        if count.isdigit():
            count = int(count)
        else:
            await ctx.channel.send(_("I can't understand how many are in your group. Just say **!here** if you're by yourself, or **!coming 5** for example if there are 5 in your group."))
            return
    elif (ctx.author.id in trainer_dict) and (sum(trainer_dict[ctx.author.id]['status'].values()) > 0):
        count = trainer_dict[ctx.author.id]['count']
    else:
        count = 1
    await _lobby(ctx.message, count)

async def _lobby(message, count):
    if 'lobby' not in guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]:
        await message.channel.send(_('There is no group in the lobby for you to join! Use **!starting** if the group waiting at the raid is entering the lobby!'))
        return
    trainer_dict = guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['trainer_dict']
    if count == 1:
        await message.channel.send(_('{member} is entering the lobby!').format(member=message.author.mention))
    else:
        await message.channel.send(_('{member} is entering the lobby with a total of {trainer_count} trainers!').format(member=message.author.mention, trainer_count=count))
    if message.author.id not in trainer_dict:
        trainer_dict[message.author.id] = {

        }
    trainer_dict[message.author.id]['status'] = {'maybe':0, 'coming':0, 'here':0, 'lobby':count}
    trainer_dict[message.author.id]['count'] = count
    guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['trainer_dict'] = trainer_dict

@Meowth.command(aliases=['x'])
@checks.raidchannel()
async def cancel(ctx):
    """Indicate you are no longer interested in a raid.

    Usage: !cancel
    Works only in raid channels. Removes you and your party
    from the list of trainers who are "otw" or "here"."""
    await _cancel(ctx.channel, ctx.author)

async def _cancel(channel, author):
    guild = channel.guild
    raidtype = _("event") if guild_dict[guild.id]['raidchannel_dict'][channel.id].get('meetup',False) else _("raid")
    try:
        t_dict = guild_dict[guild.id]['raidchannel_dict'][channel.id]['trainer_dict'][author.id]
    except KeyError:
        await channel.send(_('{member} has no status to cancel!').format(member=author.mention))
        return
    if t_dict['status']['maybe']:
        if t_dict['count'] == 1:
            await channel.send(_('{member} is no longer interested!').format(member=author.mention))
        else:
            await channel.send(_('{member} and their total of {trainer_count} trainers are no longer interested!').format(member=author.mention, trainer_count=t_dict['count']))
    if t_dict['status']['here']:
        if t_dict['count'] == 1:
            await channel.send(_('{member} has left the {raidtype}!').format(member=author.mention, raidtype=raidtype))
        else:
            await channel.send(_('{member} and their total of {trainer_count} trainers have left the {raidtype}!').format(member=author.mention, trainer_count=t_dict['count'], raidtype=raidtype))
    if t_dict['status']['coming']:
        if t_dict['count'] == 1:
            await channel.send(_('{member} is no longer on their way!').format(member=author.mention))
        else:
            await channel.send(_('{member} and their total of {trainer_count} trainers are no longer on their way!').format(member=author.mention, trainer_count=t_dict['count']))
    if t_dict['status']['lobby']:
        if t_dict['count'] == 1:
            await channel.send(_('{member} has backed out of the lobby!').format(member=author.mention))
        else:
            await channel.send(_('{member} and their total of {trainer_count} trainers have backed out of the lobby!').format(member=author.mention, trainer_count=t_dict['count']))
    t_dict['status'] = {'maybe':0, 'coming':0, 'here':0, 'lobby':0}
    t_dict['party'] = {'mystic':0, 'valor':0, 'instinct':0, 'unknown':0}
    t_dict['interest'] = []
    t_dict['count'] = 1
    await _edit_party(channel, author)
    regions = guild_dict[channel.guild.id]['raidchannel_dict'][channel.id].get('regions', None)
    if regions:
        await _update_listing_channels(guild, 'raid', edit=True, regions=regions)

async def lobby_countdown(ctx):
    await asyncio.sleep(120)
    if ('lobby' not in guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]) or (time.time() < guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['lobby']['exp']):
        return
    ctx_lobbycount = 0
    trainer_delete_list = []
    for trainer in ctx.trainer_dict:
        if ctx.trainer_dict[trainer]['status']['lobby']:
            ctx_lobbycount += ctx.trainer_dict[trainer]['status']['lobby']
            trainer_delete_list.append(trainer)
    if ctx_lobbycount > 0:
        await ctx.channel.send(_('The group of {count} in the lobby has entered the raid! Wish them luck!').format(count=str(ctx_lobbycount)))
    for trainer in trainer_delete_list:
        if team in ctx.team_names:
            ctx.trainer_dict[trainer]['status'] = {'maybe':0, 'coming':0, 'here':herecount - teamcount, 'lobby': lobbycount}
            ctx.trainer_dict[trainer]['party'][team] = 0
            ctx.trainer_dict[trainer]['count'] = ctx.trainer_dict[trainer]['count'] - teamcount
        else:
            del ctx.trainer_dict[trainer]
    try:
        del guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['lobby']
    except KeyError:
        pass
    await _edit_party(ctx.channel, ctx.author)
    guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['trainer_dict'] = ctx.trainer_dict
    regions = guild_dict[ctx.channel.guild.id]['raidchannel_dict'][ctx.channel.id].get('regions', None)
    if regions:
        await _update_listing_channels(ctx.guild, 'raid', edit=True, regions=regions)

@Meowth.command()
@checks.activeraidchannel()
async def starting(ctx, team: str = ''):
    """Signal that a raid is starting.

    Usage: !starting [team]
    Works only in raid channels. Sends a message and clears the waiting list. Users who are waiting
    for a second group must reannounce with the :here: emoji or !here."""
    channel = ctx.channel
    guild = ctx.guild
    ctx_startinglist = []
    team_list = []
    ctx.team_names = ["mystic", "valor", "instinct", "unknown"]
    team = team if team and team.lower() in ctx.team_names else "all"
    ctx.trainer_dict = copy.deepcopy(guild_dict[guild.id]['raidchannel_dict'][channel.id]['trainer_dict'])
    if guild_dict[guild.id]['raidchannel_dict'][channel.id].get('type',None) == 'egg':
        starting_str = _("How can you start when the egg hasn't hatched!?")
        await channel.send(starting_str)
        return
    if guild_dict[guild.id]['raidchannel_dict'][channel.id].get('lobby',False):
        starting_str = _("Please wait for the group in the lobby to enter the raid.")
        await channel.send(starting_str)
        return
    trainer_joined = False
    for trainer in ctx.trainer_dict:
        count = ctx.trainer_dict[trainer]['count']
        user = guild.get_member(trainer)
        if team in ctx.team_names:
            if ctx.trainer_dict[trainer]['party'][team]:
                team_list.append(user.id)
            teamcount = ctx.trainer_dict[trainer]['party'][team]
            herecount = ctx.trainer_dict[trainer]['status']['here']
            lobbycount = ctx.trainer_dict[trainer]['status']['lobby']
            if ctx.trainer_dict[trainer]['status']['here'] and (user.id in team_list):
                ctx.trainer_dict[trainer]['status'] = {'maybe':0, 'coming':0, 'here':herecount - teamcount, 'lobby':lobbycount + teamcount}
                trainer_joined = True
                ctx_startinglist.append(user.mention)
        else:
            if ctx.trainer_dict[trainer]['status']['here'] and (user.id in team_list or team == "all"):
                ctx.trainer_dict[trainer]['status'] = {'maybe':0, 'coming':0, 'here':0, 'lobby':count}
                trainer_joined = True
                ctx_startinglist.append(user.mention)
        if trainer_joined:
            joined = guild_dict[guild.id].setdefault('trainers',{}).setdefault(trainer,{}).setdefault('joined',0) + 1
            guild_dict[guild.id]['trainers'][trainer]['joined'] = joined
            
    if len(ctx_startinglist) == 0:
        starting_str = _("How can you start when there's no one waiting at this raid!?")
        await channel.send(starting_str)
        return
    guild_dict[guild.id]['raidchannel_dict'][channel.id]['trainer_dict'] = ctx.trainer_dict
    starttime = guild_dict[guild.id]['raidchannel_dict'][channel.id].get('starttime',None)
    if starttime:
        timestr = _(' to start at **{}** ').format(starttime.strftime(_('%I:%M %p (%H:%M)')))
        guild_dict[guild.id]['raidchannel_dict'][channel.id]['starttime'] = None
    else:
        timestr = ' '
    starting_str = _('Starting - The group that was waiting{timestr}is starting the raid! Trainers {trainer_list}, if you are not in this group and are waiting for the next group, please respond with {here_emoji} or **!here**. If you need to ask those that just started to back out of their lobby, use **!backout**').format(timestr=timestr, trainer_list=', '.join(ctx_startinglist), here_emoji=parse_emoji(guild, config['here_id']))
    guild_dict[guild.id]['raidchannel_dict'][channel.id]['lobby'] = {"exp":time.time() + 120, "team":team}
    if starttime:
        starting_str += '\n\nThe start time has also been cleared, new groups can set a new start time wtih **!starttime HH:MM AM/PM** (You can also omit AM/PM and use 24-hour time!).'
        report_channel = Meowth.get_channel(guild_dict[guild.id]['raidchannel_dict'][channel.id]['reportcity'])
        raidmsg = await channel.get_message(guild_dict[guild.id]['raidchannel_dict'][channel.id]['raidmessage'])
        reportmsg = await report_channel.get_message(guild_dict[guild.id]['raidchannel_dict'][channel.id]['raidreport'])
        embed = raidmsg.embeds[0]
        embed.set_field_at(2, name=_("**Next Group**"), value=_("Set with **!starttime**"), inline=True)
        try:
            await raidmsg.edit(content=raidmsg.content,embed=embed)
        except discord.errors.NotFound:
            pass
        try:
            await reportmsg.edit(content=reportmsg.content,embed=embed)
        except discord.errors.NotFound:
            pass
    await channel.send(starting_str)
    ctx.bot.loop.create_task(lobby_countdown(ctx))

@Meowth.command()
@checks.activeraidchannel()
async def backout(ctx):
    """Request players in lobby to backout

    Usage: !backout
    Will alert all trainers in the lobby that a backout is requested."""
    message = ctx.message
    channel = message.channel
    author = message.author
    guild = channel.guild
    trainer_dict = guild_dict[guild.id]['raidchannel_dict'][channel.id]['trainer_dict']
    if (author.id in trainer_dict) and (trainer_dict[author.id]['status']['lobby']):
        count = trainer_dict[author.id]['count']
        trainer_dict[author.id]['status'] = {'maybe':0, 'coming':0,'here':count,'lobby':0}
        lobby_list = []
        for trainer in trainer_dict:
            count = trainer_dict[trainer]['count']
            if trainer_dict[trainer]['status']['lobby']:
                user = guild.get_member(trainer)
                lobby_list.append(user.mention)
                trainer_dict[trainer]['status'] = {'maybe':0, 'coming':0, 'here':count, 'lobby':0}
        if (not lobby_list):
            await channel.send(_("There's no one else in the lobby for this raid!"))
            try:
                del guild_dict[guild.id]['raidchannel_dict'][channel.id]['lobby']
            except KeyError:
                pass
            return
        await channel.send(_('Backout - {author} has indicated that the group consisting of {lobby_list} and the people with them has backed out of the lobby! If this is inaccurate, please use **!lobby** or **!cancel** to help me keep my lists accurate!').format(author=author.mention, lobby_list=', '.join(lobby_list)))
        try:
            del guild_dict[guild.id]['raidchannel_dict'][channel.id]['lobby']
        except KeyError:
            pass
    else:
        lobby_list = []
        trainer_list = []
        for trainer in trainer_dict:
            if trainer_dict[trainer]['status']['lobby']:
                user = guild.get_member(trainer)
                lobby_list.append(user.mention)
                trainer_list.append(trainer)
        if (not lobby_list):
            await channel.send(_("There's no one in the lobby for this raid!"))
            return

        backoutmsg = await channel.send(_('Backout - {author} has requested a backout! If one of the following trainers reacts with the check mark, I will assume the group is backing out of the raid lobby as requested! {lobby_list}').format(author=author.mention, lobby_list=', '.join(lobby_list)))
        try:
            timeout = False
            res, reactuser = await ask(backoutmsg, channel, trainer_list, react_list=['✅'])
        except TypeError:
            timeout = True
        if not timeout and res.emoji == '✅':
            for trainer in trainer_list:
                count = trainer_dict[trainer]['count']
                if trainer in trainer_dict:
                    trainer_dict[trainer]['status'] = {'maybe':0, 'coming':0, 'here':count, 'lobby':0}
            await channel.send(_('{user} confirmed the group is backing out!').format(user=reactuser.mention))
            try:
                del guild_dict[guild.id]['raidchannel_dict'][channel.id]['lobby']
            except KeyError:
                pass
        else:
            return

"""
List Commands
"""
async def _get_raid_listing_messages(channel, region=None):
    '''
    listings_enabled | region_set | result
    ======================================
            Y        |      Y     |   get for region only (regional listings configured)
            Y        |      N     |   get for all regions (listings configured -- one channel)
            N        |      Y     |   normal list for region only (list command enabled in regional channel)
            N        |      N     |   normal list (all regions -- list command enabled)
    '''
    guild = channel.guild
    listmsg_list = []
    listmsg = ""
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])
    listing_dict = guild_dict[guild.id]['configure_dict']['raid'].get('listings', {})
    listing_enabled = listing_dict.get('enabled', False)
    rc_d = guild_dict[guild.id]['raidchannel_dict']
    if region:
        cty = region
    else:
        cty = channel.name
    raid_dict = {}
    egg_dict = {}
    exraid_list = []
    event_list = []
    for r in rc_d:
        if region:
            reportlocation = rc_d[r].get('regions', [])
        elif listing_enabled and 'channel' in listing_dict:
            reportlocation = [Meowth.get_channel(listing_dict['channel']).name]
        else: 
            reportlocation = [Meowth.get_channel(rc_d[r]['reportcity']).name]
        if not reportlocation:
            continue
        if (cty in reportlocation) and rc_d[r]['active'] and discord.utils.get(guild.text_channels, id=r):
            exp = rc_d[r]['exp']
            type = rc_d[r]['type']
            level = rc_d[r]['egglevel']
            if (type == 'egg') and level.isdigit():
                egg_dict[r] = exp
            elif rc_d[r].get('meetup',{}):
                event_list.append(r)
            elif ((type == 'exraid') or (level == 'EX')):
                exraid_list.append(r)
            else:
                raid_dict[r] = exp

    def list_output(r):
        trainer_dict = rc_d[r]['trainer_dict']
        rchan = Meowth.get_channel(r)
        end = now + datetime.timedelta(seconds=rc_d[r]['exp'] - time.time())
        output = ''
        start_str = ''
        t_emoji = ''
        ex_eligibility = ''
        ctx_herecount = 0
        ctx_comingcount = 0
        ctx_maybecount = 0
        ctx_lobbycount = 0
        for trainer in rc_d[r]['trainer_dict'].keys():
            if not guild.get_member(trainer):
                continue
            if trainer_dict[trainer]['status']['here']:
                ctx_herecount += trainer_dict[trainer]['count']
            elif trainer_dict[trainer]['status']['coming']:
                ctx_comingcount += trainer_dict[trainer]['count']
            elif trainer_dict[trainer]['status']['maybe']:
                ctx_maybecount += trainer_dict[trainer]['count']
            elif trainer_dict[trainer]['status']['lobby']:
                ctx_lobbycount += trainer_dict[trainer]['count']
        if rc_d[r]['manual_timer'] == False:
            assumed_str = _(' (assumed)')
        else:
            assumed_str = ''
        starttime = rc_d[r].get('starttime',None)
        meetup = rc_d[r].get('meetup',{})
        if starttime and starttime > now and not meetup:
            start_str = _(' **Next Group**: {}').format(starttime.strftime(_('%I:%M%p')))
        else:
            starttime = False
        egglevel = rc_d[r]['egglevel']
        if egglevel.isdigit() and (int(egglevel) > 0):
            t_emoji = str(egglevel) + '\u20e3'
            expirytext = _(' - Hatches: {expiry}{is_assumed}').format(expiry=end.strftime(_('%I:%M%p')), is_assumed=assumed_str)
        elif ((rc_d[r]['egglevel'] == 'EX') or (rc_d[r]['type'] == 'exraid')) and not meetup:
            expirytext = _(' - Hatches: {expiry}{is_assumed}').format(expiry=end.strftime(_('%B %d at %I:%M%p')), is_assumed=assumed_str)
        elif meetup:
            meetupstart = meetup['start']
            meetupend = meetup['end']
            expirytext = ""
            if meetupstart:
                expirytext += _(' - Starts: {expiry}{is_assumed}').format(expiry=meetupstart.strftime(_('%B %d at %I:%M%p')), is_assumed=assumed_str)
            if meetupend:
                expirytext += _(" - Ends: {expiry}{is_assumed}").format(expiry=meetupend.strftime(_('%B %d at %I:%M%p')), is_assumed=assumed_str)
            if not meetupstart and not meetupend:
                expirytext = _(' - Starts: {expiry}{is_assumed}').format(expiry=end.strftime(_('%B %d at %I:%M%p')), is_assumed=assumed_str)
        else:
            expirytext = _(' - **Expires**: {expiry}{is_assumed}').format(expiry=end.strftime(_('%I:%M%p')), is_assumed=assumed_str)
        boss = Pokemon.get_pokemon(Meowth, rc_d[r].get('pokemon', ''))
        if not t_emoji and boss:
            t_emoji = str(boss.raid_level) + '\u20e3'
        gym = rc_d[r].get('gym', None)
        if gym:
            ex_eligibility = ' *EX-Eligible*' if gym.ex_eligible else ''
        enabled = raid_channels_enabled(guild, rchan)
        if enabled:
            output += _('\t{tier} {raidchannel}{ex_eligibility}{expiry_text} ({total_count} players){starttime}\n').format(tier=t_emoji, raidchannel=rchan.mention, ex_eligibility=ex_eligibility, expiry_text=expirytext, total_count=sum([ctx_maybecount, ctx_comingcount, ctx_herecount, ctx_lobbycount]), starttime=start_str)
        else:
            channel_name = rchan.name.replace('_',': ').replace('-', ' ').title()
            map_url = ''
            map_url = rc_d[r]['gym'].maps_url
            try:
                map_url = rc_d[r]['gym'].maps_url
            except:
                pass
            output += _('\t{tier} **{raidchannel}**{ex_eligibility}{expiry_text} \nDirections: {map_url}\n').format(tier=t_emoji, raidchannel=channel_name, ex_eligibility=ex_eligibility, expiry_text=expirytext, total_count=sum([ctx_maybecount, ctx_comingcount, ctx_herecount, ctx_lobbycount]), starttime=start_str,map_url=map_url)
        return output
    
    def process_category(listmsg_list, category_title, category_list):
        listmsg = f"**{category_title}:**\n"
        for r in category_list:
            new_msg = list_output(r)
            if len(listmsg) + len(new_msg) < constants.MAX_MESSAGE_LENGTH:
                listmsg += new_msg
            else:
                listmsg_list.append(listmsg)
                listmsg = f"**{category_title}:** (continued)\n"
                listmsg += new_msg
        listmsg += '\n'
        return listmsg

    activeraidnum = len(raid_dict) + len(egg_dict)
    if not listing_enabled:
        activeraidnum += len(exraid_list) + len(event_list)
    if activeraidnum:
        listmsg += _("**Current eggs and raids reported in {0}**\n\n").format(cty.capitalize())
        if raid_dict:
            listmsg += process_category(listmsg_list, "Active Raids", [r for (r, __) in sorted(raid_dict.items(), key=itemgetter(1))])
        if egg_dict:
            listmsg += process_category(listmsg_list, "Raid Eggs", [r for (r, __) in sorted(egg_dict.items(), key=itemgetter(1))])
        if exraid_list and not listing_enabled:
            listmsg += process_category(listmsg_list, "EX Raids", exraid_list)
        if event_list and not listing_enabled:
            listmsg += process_category(listmsg_list, "Meetups", event_list)
    else:
        listmsg = _('No active raids! Report one with **!raid <name> <location> [weather] [timer]**.')
    listmsg_list.append(listmsg)
    return listmsg_list

@Meowth.group(name="list", aliases=['lists'], case_insensitive=True)
async def _list(ctx):
    """Lists all raid info for the current channel.

    Usage: !list
    Works only in raid or city channels. Calls the interested, waiting, and here lists. Also prints
    the raid timer. In city channels, lists all active raids."""
    if ctx.invoked_subcommand == None:
        listmsg = ""
        guild = ctx.guild
        channel = ctx.channel
        now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[guild.id]['configure_dict']['settings']['offset'])
        if checks.check_raidreport(ctx) or checks.check_exraidreport(ctx):
            raid_dict = guild_dict[guild.id]['configure_dict']['raid']
            if raid_dict.get('listings', {}).get('enabled', False):
                msg = await ctx.channel.send("*Raid list command disabled when listings are provided by server*")
                await asyncio.sleep(10)
                await msg.delete()
                await ctx.message.delete()
                return
            region = None
            if guild_dict[guild.id]['configure_dict'].get('regions', {}).get('enabled', False) and raid_dict.get('categories', None) == 'region':
                region = raid_dict.get('category_dict', {}).get(channel.id, None)
            listmsg = await _get_listing_messages('raid', channel, region)
        elif checks.check_raidactive(ctx):
            team_list = ["mystic","valor","instinct","unknown"]
            tag = False
            team = False
            starttime = guild_dict[guild.id]['raidchannel_dict'][channel.id].get('starttime',None)
            meetup = guild_dict[guild.id]['raidchannel_dict'][channel.id].get('meetup',{})
            rc_d = guild_dict[guild.id]['raidchannel_dict'][channel.id]
            list_split = ctx.message.clean_content.lower().split()
            if "tags" in list_split or "tag" in list_split:
                tag = True
            for word in list_split:
                if word in team_list:
                    team = word.lower()
                    break
            if team == "mystic" or team == "valor" or team == "instinct":
                bulletpoint = parse_emoji(ctx.guild, config['team_dict'][team])
            elif team == "unknown":
                bulletpoint = '❔'
            else:
                bulletpoint = '🔹'
            if " 0 interested!" not in await _interest(ctx, tag, team):
                listmsg += ('\n' + bulletpoint) + (await _interest(ctx, tag, team))
            if " 0 on the way!" not in await _otw(ctx, tag, team):
                listmsg += ('\n' + bulletpoint) + (await _otw(ctx, tag, team))
            if " 0 waiting at the raid!" not in await _waiting(ctx, tag, team):
                listmsg += ('\n' + bulletpoint) + (await _waiting(ctx, tag, team))
            if " 0 in the lobby!" not in await _lobbylist(ctx, tag, team):
                listmsg += ('\n' + bulletpoint) + (await _lobbylist(ctx, tag, team))
            if (len(listmsg.splitlines()) <= 1):
                listmsg +=  ('\n' + bulletpoint) + (_(" Nobody has updated their status yet!"))
            listmsg += ('\n' + bulletpoint) + (await print_raid_timer(channel))
            if starttime and (starttime > now) and not meetup:
                listmsg += _('\nThe next group will be starting at **{}**').format(starttime.strftime(_('%I:%M %p (%H:%M)')))
            await channel.send(listmsg)
            return
        else:
            raise checks.errors.CityRaidChannelCheckFail()

@_list.command()
@checks.activechannel()
async def interested(ctx, tags: str = ''):
    """Lists the number and users who are interested in the raid.

    Usage: !list interested
    Works only in raid channels."""
    if tags and tags.lower() == "tags" or tags.lower() == "tag":
        tags = True
    listmsg = await _interest(ctx, tags)
    await ctx.channel.send(listmsg)

async def _interest(ctx, tag=False, team=False):
    ctx_maybecount = 0
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[ctx.channel.guild.id]['configure_dict']['settings']['offset'])
    trainer_dict = copy.deepcopy(guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['trainer_dict'])
    maybe_exstr = ''
    maybe_list = []
    name_list = []
    for trainer in trainer_dict.keys():
        user = ctx.guild.get_member(trainer)
        if (trainer_dict[trainer]['status']['maybe']) and user and team == False:
            ctx_maybecount += trainer_dict[trainer]['status']['maybe']
            if trainer_dict[trainer]['status']['maybe'] == 1:
                name_list.append(_('**{name}**').format(name=user.display_name))
                maybe_list.append(user.mention)
            else:
                name_list.append(_('**{name} ({count})**').format(name=user.display_name, count=trainer_dict[trainer]['status']['maybe']))
                maybe_list.append(_('{name} **({count})**').format(name=user.mention, count=trainer_dict[trainer]['status']['maybe']))
        elif (trainer_dict[trainer]['status']['maybe']) and user and team and trainer_dict[trainer]['party'][team]:
            if trainer_dict[trainer]['status']['maybe'] == 1:
                name_list.append(_('**{name}**').format(name=user.display_name))
                maybe_list.append(user.mention)
            else:
                name_list.append(_('**{name} ({count})**').format(name=user.display_name, count=trainer_dict[trainer]['party'][team]))
                maybe_list.append(_('{name} **({count})**').format(name=user.mention, count=trainer_dict[trainer]['party'][team]))
            ctx_maybecount += trainer_dict[trainer]['party'][team]

    if ctx_maybecount > 0:
        if (now.time() >= datetime.time(5, 0)) and (now.time() <= datetime.time(21, 0)) and (tag == True):
            maybe_exstr = _(' including {trainer_list} and the people with them! Let them know if there is a group forming').format(trainer_list=', '.join(maybe_list))
        else:
            maybe_exstr = _(' including {trainer_list} and the people with them! Let them know if there is a group forming').format(trainer_list=', '.join(name_list))
    listmsg = _(' {trainer_count} interested{including_string}!').format(trainer_count=str(ctx_maybecount), including_string=maybe_exstr)
    return listmsg

@_list.command()
@checks.activechannel()
async def coming(ctx, tags: str = ''):
    """Lists the number and users who are coming to a raid.

    Usage: !list coming
    Works only in raid channels."""
    if tags and tags.lower() == "tags" or tags.lower() == "tag":
        tags = True
    listmsg = await _otw(ctx, tags)
    await ctx.channel.send(listmsg)

async def _otw(ctx, tag=False, team=False):
    ctx_comingcount = 0
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[ctx.channel.guild.id]['configure_dict']['settings']['offset'])
    trainer_dict = copy.deepcopy(guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['trainer_dict'])
    otw_exstr = ''
    otw_list = []
    name_list = []
    for trainer in trainer_dict.keys():
        user = ctx.guild.get_member(trainer)
        if (trainer_dict[trainer]['status']['coming']) and user and team == False:
            ctx_comingcount += trainer_dict[trainer]['status']['coming']
            if trainer_dict[trainer]['status']['coming'] == 1:
                name_list.append(_('**{name}**').format(name=user.display_name))
                otw_list.append(user.mention)
            else:
                name_list.append(_('**{name} ({count})**').format(name=user.display_name, count=trainer_dict[trainer]['status']['coming']))
                otw_list.append(_('{name} **({count})**').format(name=user.mention, count=trainer_dict[trainer]['status']['coming']))
        elif (trainer_dict[trainer]['status']['coming']) and user and team and trainer_dict[trainer]['party'][team]:
            if trainer_dict[trainer]['status']['coming'] == 1:
                name_list.append(_('**{name}**').format(name=user.display_name))
                otw_list.append(user.mention)
            else:
                name_list.append(_('**{name} ({count})**').format(name=user.display_name, count=trainer_dict[trainer]['party'][team]))
                otw_list.append(_('{name} **({count})**').format(name=user.mention, count=trainer_dict[trainer]['party'][team]))
            ctx_comingcount += trainer_dict[trainer]['party'][team]

    if ctx_comingcount > 0:
        if (now.time() >= datetime.time(5, 0)) and (now.time() <= datetime.time(21, 0)) and (tag == True):
            otw_exstr = _(' including {trainer_list} and the people with them! Be considerate and wait for them if possible').format(trainer_list=', '.join(otw_list))
        else:
            otw_exstr = _(' including {trainer_list} and the people with them! Be considerate and wait for them if possible').format(trainer_list=', '.join(name_list))
    listmsg = _(' {trainer_count} on the way{including_string}!').format(trainer_count=str(ctx_comingcount), including_string=otw_exstr)
    return listmsg

@_list.command()
@checks.activechannel()
async def here(ctx, tags: str = ''):
    """List the number and users who are present at a raid.

    Usage: !list here
    Works only in raid channels."""
    if tags and tags.lower() == "tags" or tags.lower() == "tag":
        tags = True
    listmsg = await _waiting(ctx, tags)
    await ctx.channel.send(listmsg)

async def _waiting(ctx, tag=False, team=False):
    ctx_herecount = 0
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[ctx.channel.guild.id]['configure_dict']['settings']['offset'])
    raid_dict = copy.deepcopy(guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id])
    trainer_dict = copy.deepcopy(guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['trainer_dict'])
    here_exstr = ''
    here_list = []
    name_list = []
    for trainer in trainer_dict.keys():
        user = ctx.guild.get_member(trainer)
        if (trainer_dict[trainer]['status']['here']) and user and team == False:
            ctx_herecount += trainer_dict[trainer]['status']['here']
            if trainer_dict[trainer]['status']['here'] == 1:
                name_list.append(_('**{name}**').format(name=user.display_name))
                here_list.append(user.mention)
            else:
                name_list.append(_('**{name} ({count})**').format(name=user.display_name, count=trainer_dict[trainer]['status']['here']))
                here_list.append(_('{name} **({count})**').format(name=user.mention, count=trainer_dict[trainer]['status']['here']))
        elif (trainer_dict[trainer]['status']['here']) and user and team and trainer_dict[trainer]['party'][team]:
            if trainer_dict[trainer]['status']['here'] == 1:
                name_list.append(_('**{name}**').format(name=user.display_name))
                here_list.append(user.mention)
            else:
                name_list.append(_('**{name} ({count})**').format(name=user.display_name, count=trainer_dict[trainer]['party'][team]))
                here_list.append(_('{name} **({count})**').format(name=user.mention, count=trainer_dict[trainer]['party'][team]))
            ctx_herecount += trainer_dict[trainer]['party'][team]
            if raid_dict.get('lobby',{"team":"all"})['team'] == team or raid_dict.get('lobby',{"team":"all"})['team'] == "all":
                ctx_herecount -= trainer_dict[trainer]['status']['lobby']
    raidtype = _("event") if guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id].get('meetup',False) else _("raid")
    if ctx_herecount > 0:
        if (now.time() >= datetime.time(5, 0)) and (now.time() <= datetime.time(21, 0)) and (tag == True):
            here_exstr = _(" including {trainer_list} and the people with them! Be considerate and let them know if and when you'll be there").format(trainer_list=', '.join(here_list))
        else:
            here_exstr = _(" including {trainer_list} and the people with them! Be considerate and let them know if and when you'll be there").format(trainer_list=', '.join(name_list))
    listmsg = _(' {trainer_count} waiting at the {raidtype}{including_string}!').format(trainer_count=str(ctx_herecount), raidtype=raidtype, including_string=here_exstr)
    return listmsg

@_list.command()
@checks.activeraidchannel()
async def lobby(ctx, tag=False):
    """List the number and users who are in the raid lobby.

    Usage: !list lobby
    Works only in raid channels."""
    listmsg = await _lobbylist(ctx)
    await ctx.channel.send(listmsg)

async def _lobbylist(ctx, tag=False, team=False):
    ctx_lobbycount = 0
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=guild_dict[ctx.channel.guild.id]['configure_dict']['settings']['offset'])
    raid_dict = copy.deepcopy(guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id])
    trainer_dict = copy.deepcopy(guild_dict[ctx.guild.id]['raidchannel_dict'][ctx.channel.id]['trainer_dict'])
    lobby_exstr = ''
    lobby_list = []
    name_list = []
    for trainer in trainer_dict.keys():
        user = ctx.guild.get_member(trainer)
        if (trainer_dict[trainer]['status']['lobby']) and user and team == False:
            ctx_lobbycount += trainer_dict[trainer]['status']['lobby']
            if trainer_dict[trainer]['status']['lobby'] == 1:
                name_list.append(_('**{name}**').format(name=user.display_name))
                lobby_list.append(user.mention)
            else:
                name_list.append(_('**{name} ({count})**').format(name=user.display_name, count=trainer_dict[trainer]['status']['lobby']))
                lobby_list.append(_('{name} **({count})**').format(name=user.mention, count=trainer_dict[trainer]['status']['lobby']))
        elif (trainer_dict[trainer]['status']['lobby']) and user and team and trainer_dict[trainer]['party'][team]:
            if trainer_dict[trainer]['status']['lobby'] == 1:
                name_list.append(_('**{name}**').format(name=user.display_name))
                lobby_list.append(user.mention)
            else:
                name_list.append(_('**{name} ({count})**').format(name=user.display_name, count=trainer_dict[trainer]['party'][team]))
                lobby_list.append(_('{name} **({count})**').format(name=user.mention, count=trainer_dict[trainer]['party'][team]))
            if raid_dict.get('lobby',{"team":"all"})['team'] == team or raid_dict.get('lobby',{"team":"all"})['team'] == "all":
                ctx_lobbycount += trainer_dict[trainer]['party'][team]

    if ctx_lobbycount > 0:
        if (now.time() >= datetime.time(5, 0)) and (now.time() <= datetime.time(21, 0)) and (tag == True):
            lobby_exstr = _(' including {trainer_list} and the people with them! Use **!lobby** if you are joining them or **!backout** to request a backout').format(trainer_list=', '.join(lobby_list))
        else:
            lobby_exstr = _(' including {trainer_list} and the people with them! Use **!lobby** if you are joining them or **!backout** to request a backout').format(trainer_list=', '.join(name_list))
    listmsg = _(' {trainer_count} in the lobby{including_string}!').format(trainer_count=str(ctx_lobbycount), including_string=lobby_exstr)
    return listmsg

@_list.command()
@checks.activeraidchannel()
async def bosses(ctx):
    """List each possible boss and the number of users that have RSVP'd for it.

    Usage: !list bosses
    Works only in raid channels."""
    listmsg = await _bosslist(ctx)
    await ctx.channel.send(listmsg)

async def _bosslist(ctx):
    message = ctx.message
    channel = ctx.channel
    egglevel = guild_dict[message.guild.id]['raidchannel_dict'][channel.id]['egglevel']
    egg_level = str(egglevel)
    egg_info = raid_info['raid_eggs'][egg_level]
    egg_img = egg_info['egg_img']
    boss_dict = {}
    boss_list = []
    boss_dict["unspecified"] = {"type": "❔", "total": 0, "maybe": 0, "coming": 0, "here": 0}
    for entry in egg_info['pokemon']:
        p = Pokemon.get_pokemon(Meowth, entry)
        name = str(p).lower()
        boss_list.append(name)
        boss_dict[name] = {"type": types_to_str(message.guild, p.types), "total": 0, "maybe": 0, "coming": 0, "here": 0}
    boss_list.append('unspecified')
    trainer_dict = copy.deepcopy(guild_dict[message.guild.id]['raidchannel_dict'][channel.id]['trainer_dict'])
    for trainer in trainer_dict:
        if not ctx.guild.get_member(trainer):
            continue
        interest = trainer_dict[trainer].get('interest', ['unspecified'])
        for item in interest:
            status = max(trainer_dict[trainer]['status'], key=lambda key: trainer_dict[trainer]['status'][key])
            count = trainer_dict[trainer]['count']
            boss_dict[item][status] += count
            boss_dict[item]['total'] += count
    bossliststr = ''
    for boss in boss_list:
        if boss_dict[boss]['total'] > 0:
            bossliststr += _('{type}{name}: **{total} total,** {interested} interested, {coming} coming, {here} waiting{type}\n').format(type=boss_dict[boss]['type'],name=boss.capitalize(), total=boss_dict[boss]['total'], interested=boss_dict[boss]['maybe'], coming=boss_dict[boss]['coming'], here=boss_dict[boss]['here'])
    if bossliststr:
        listmsg = _(' Boss numbers for the raid:\n{}').format(bossliststr)
    else:
        listmsg = _(' Nobody has told me what boss they want!')
    return listmsg

@_list.command()
@checks.activechannel()
async def teams(ctx):
    """List the teams for the users that have RSVP'd to a raid.

    Usage: !list teams
    Works only in raid channels."""
    listmsg = await _teamlist(ctx)
    await ctx.channel.send(listmsg)

async def _teamlist(ctx):
    message = ctx.message
    team_dict = {}
    team_dict["mystic"] = {"total":0,"maybe":0,"coming":0,"here":0}
    team_dict["valor"] = {"total":0,"maybe":0,"coming":0,"here":0}
    team_dict["instinct"] = {"total":0,"maybe":0,"coming":0,"here":0}
    team_dict["unknown"] = {"total":0,"maybe":0,"coming":0,"here":0}
    status_list = ["here","coming","maybe"]
    team_list = ["mystic","valor","instinct","unknown"]
    teamliststr = ''
    trainer_dict = copy.deepcopy(guild_dict[message.guild.id]['raidchannel_dict'][message.channel.id]['trainer_dict'])
    for trainer in trainer_dict.keys():
        if not ctx.guild.get_member(trainer):
            continue
        for team in team_list:
            team_dict[team]["total"] += int(trainer_dict[trainer]['party'][team])
            for status in status_list:
                if max(trainer_dict[trainer]['status'], key=lambda key: trainer_dict[trainer]['status'][key]) == status:
                    team_dict[team][status] += int(trainer_dict[trainer]['party'][team])
    for team in team_list[:-1]:
        if team_dict[team]['total'] > 0:
            teamliststr += _('{emoji} **{total} total,** {interested} interested, {coming} coming, {here} waiting {emoji}\n').format(emoji=parse_emoji(ctx.guild, config['team_dict'][team]), total=team_dict[team]['total'], interested=team_dict[team]['maybe'], coming=team_dict[team]['coming'], here=team_dict[team]['here'])
    if team_dict["unknown"]['total'] > 0:
        teamliststr += '❔ '
        teamliststr += _('**{grey_number} total,** {greymaybe} interested, {greycoming} coming, {greyhere} waiting')
        teamliststr += ' ❔'
        teamliststr = teamliststr.format(grey_number=team_dict['unknown']['total'], greymaybe=team_dict['unknown']['maybe'], greycoming=team_dict['unknown']['coming'], greyhere=team_dict['unknown']['here'])
    if teamliststr:
        listmsg = _(' Team numbers for the raid:\n{}').format(teamliststr)
    else:
        listmsg = _(' Nobody has updated their status!')
    return listmsg

@_list.command()
@checks.allowresearchreport()
async def research(ctx):
    """List the quests for the channel

    Usage: !list research"""
    research_dict = guild_dict[ctx.guild.id]['configure_dict']['research']
    if research_dict.get('listings', {}).get('enabled', False):
        msg = await ctx.channel.send("*Research list command disabled when listings are provided by server*")
        await asyncio.sleep(10)
        await msg.delete()
        await ctx.message.delete()
        return
    listmsg_list = await _researchlist(ctx)
    for listmsg in listmsg_list:
        await ctx.channel.send(embed=discord.Embed(colour=ctx.guild.me.colour, description=listmsg))

async def _researchlist(ctx):
    return await _get_listing_messages('research', ctx.message.channel)

async def _get_research_listing_messages(channel, region=None):
    guild = channel.guild
    if region:
        loc = region
    else:
        loc = channel.name
    research_dict = copy.deepcopy(guild_dict[guild.id].setdefault('questreport_dict', {}))
    research_dict = dict(sorted(research_dict.items(), key=lambda i: (i[1]['quest'], i[1]['reward'], i[1]['location'])))
    questctr = 0
    listmsg_list = []
    listmsg = f"**Here are the active research reports for {loc.capitalize()}**\n"
    current_category = ""
    for questid in research_dict:
        newmsg = ""
        try:
            report_channel = guild.get_channel(research_dict[questid]['reportchannel'])
        except:
            continue
        if not region or region in _get_channel_regions(report_channel, 'research'):
            try:
                await report_channel.get_message(questid) # verify quest message exists
                cat = research_dict[questid]['quest'].title()
                if current_category != cat:
                    current_category = cat
                    newmsg += f"\n\n**{current_category}**"
                newmsg += ('\n\t🔹')
                newmsg += _("**Reward**: {reward}, **Pokestop**: [{location}]({url})").format(location=research_dict[questid]['location'].title(), reward=research_dict[questid]['reward'].title(), url=research_dict[questid].get('url',None))
                if len(listmsg) + len(newmsg) < constants.MAX_MESSAGE_LENGTH:
                    listmsg += newmsg
                else:
                    listmsg_list.append(listmsg)
                    if current_category not in newmsg:
                        newmsg = f"**({current_category} continued)**"
                    listmsg = newmsg
                questctr += 1
            except discord.errors.NotFound:
                continue    
    if questctr == 0:
        listmsg = "There are no active research reports. Report one with **!research**"
    listmsg_list.append(listmsg)
    return listmsg_list

async def _get_wild_listing_messages(channel, region=None):
    guild = channel.guild
    if region:
        loc = region
    else:
        loc = channel.name
    wild_dict = copy.deepcopy(guild_dict[guild.id].get('wildreport_dict',{}))
    wild_dict = dict(sorted(wild_dict.items(), key=lambda i: (i[1]['pokemon'], i[1]['location'])))
    wildctr = 0
    listmsg_list = []
    listmsg = f"**Here are the active wild reports for {loc.capitalize()}**\n"
    for wildid in wild_dict:
        newmsg = ""
        try:
            report_channel = guild.get_channel(wild_dict[wildid]['reportchannel'])
        except:
            continue
        if not region or region in _get_channel_regions(report_channel, 'wild'):
            try:
                await report_channel.get_message(wildid)
                newmsg += ('\n🔹')
                newmsg += _("**Pokemon**: {pokemon}, **Location**: [{location}]({url})").format(pokemon=wild_dict[wildid]['pokemon'].title(),location=wild_dict[wildid]['location'].title(),url=wild_dict[wildid].get('url',None))
                if len(listmsg) + len(newmsg) < constants.MAX_MESSAGE_LENGTH:
                    listmsg += newmsg
                else:
                    listmsg_list.append(listmsg)
                    listmsg = newmsg
                wildctr += 1
            except discord.errors.NotFound:
                continue
    if wildctr == 0:
        listmsg = "There are no active wild pokemon. Report one with **!wild <pokemon> <location>**"
    listmsg_list.append(listmsg)
    return listmsg_list

@_list.command()
@checks.allowwildreport()
async def wilds(ctx):
    """List the wilds for the channel

    Usage: !list wilds"""
    wild_dict = guild_dict[ctx.guild.id]['configure_dict']['wild']
    if wild_dict.get('listings', {}).get('enabled', False):
        msg = await ctx.channel.send("*Wild list command disabled when listings are provided by server*")
        await asyncio.sleep(10)
        await msg.delete()
        await ctx.message.delete()
        return
    listmsg_list = await _wildlist(ctx)
    for listmsg in listmsg_list:
        await ctx.channel.send(embed=discord.Embed(colour=ctx.guild.me.colour, description=listmsg))

async def _wildlist(ctx):
    return await _get_listing_messages('wild', ctx.message.channel)

try:
    event_loop.run_until_complete(Meowth.start(config['bot_token']))
except discord.LoginFailure:
    logger.critical('Invalid token')
    event_loop.run_until_complete(Meowth.logout())
    Meowth._shutdown_mode = 0
except KeyboardInterrupt:
    logger.info('Keyboard interrupt detected. Quitting...')
    event_loop.run_until_complete(Meowth.logout())
    Meowth._shutdown_mode = 0
except Exception as e:
    logger.critical('Fatal exception', exc_info=e)
    event_loop.run_until_complete(Meowth.logout())
finally:
    pass
sys.exit(Meowth._shutdown_mode)
