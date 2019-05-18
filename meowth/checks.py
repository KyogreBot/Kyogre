
from discord.ext import commands
import discord.utils
from meowth import errors

def is_user_owner_check(config,userid):
    owner = config['master']
    return userid == owner

def is_user_dev_check(userid):
    dev_list = [454869333764603904,371387628093833216]
    return userid in dev_list

def is_user_dev_or_owner(config,userid):
    if is_user_dev_check(userid) or is_user_owner_check(config,userid):
        return True
    else:
        return False

def is_owner_check(ctx):
    author = ctx.author.id
    owner = ctx.bot.config['master']
    return author == owner

def is_owner():
    return commands.check(is_owner_check)

def is_dev_check(ctx):
    author = ctx.author.id
    dev_list = [454869333764603904,371387628093833216]
    return author in dev_list

def is_dev_or_owner():
    def predicate(ctx):
        if is_dev_check(ctx) or is_owner_check(ctx):
            return True
        else:
            return False
    return commands.check(predicate)

def is_good_standing(ctx):
    guild = ctx.guild
    if not guild:
        return False
    return ctx.bot.guild_dict[guild.id]['trainers'].setdefault('info', {}).get(ctx.author.id, {}).get('is_banned', False)

def check_permissions(ctx, perms):
    if not perms:
        return False
    ch = ctx.channel
    author = ctx.author
    resolved = ch.permissions_for(author)
    return all((getattr(resolved, name, None) == value for (name, value) in perms.items()))

def role_or_permissions(ctx, check, **perms):
    if check_permissions(ctx, perms):
        return True
    ch = ctx.channel
    author = ctx.author
    if ch.is_private:
        return False
    role = discord.utils.find(check, author.roles)
    return role is not None

def serverowner_or_permissions(**perms):
    def predicate(ctx):
        owner = ctx.guild.owner
        if ctx.author.id == owner.id:
            return True
        return check_permissions(ctx, perms)
    return commands.check(predicate)

def serverowner():
    return serverowner_or_permissions()

#configuration
def check_subscriptionset(ctx):
    if ctx.guild is None:
        return False
    guild = ctx.guild
    return ctx.bot.guild_dict[guild.id]['configure_dict'].get('subscriptions', {}).get('enabled',False)

def check_subscriptionchannel(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    subscription_channels = ctx.bot.guild_dict[guild.id]['configure_dict'].get('subscriptions', {}).get('report_channels',[])
    return channel.id in subscription_channels

def check_pvpset(ctx):
    if ctx.guild is None:
        return False
    guild = ctx.guild
    return ctx.bot.guild_dict[guild.id]['configure_dict'].get('pvp', {}).get('enabled',False)

def check_joinset(ctx):
    if ctx.guild is None:
        return False
    guild = ctx.guild
    return ctx.bot.guild_dict[guild.id]['configure_dict'].get('join', {}).get('enabled',False)

def check_pvpchannel(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    pvp_channels = ctx.bot.guild_dict[guild.id]['configure_dict'].get('pvp', {}).get('report_channels',[])
    return channel.id in pvp_channels

def check_citychannel(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    channel_list = [x for x in ctx.bot.guild_dict[guild.id]['configure_dict']['raid'].get('report_channels',{}).keys()]
    channel_list.extend([x for x in ctx.bot.guild_dict[guild.id]['configure_dict']['exraid'].get('report_channels',{}).keys()])
    channel_list.extend([x for x in ctx.bot.guild_dict[guild.id]['configure_dict']['wild'].get('report_channels',{}).keys()])
    channel_list.extend([x for x in ctx.bot.guild_dict[guild.id]['configure_dict']['research'].get('report_channels',{}).keys()])
    return channel.id in channel_list

def check_raidset(ctx):
    if ctx.guild is None:
        return False
    guild = ctx.guild
    return ctx.bot.guild_dict[guild.id]['configure_dict']['raid'].get('enabled',False)

def check_raidreport(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    channel_list = [x for x in ctx.bot.guild_dict[guild.id]['configure_dict']['raid'].get('report_channels',{}).keys()]
    return channel.id in channel_list

def check_raidchannel(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    raid_channels = ctx.bot.guild_dict[guild.id]['raidchannel_dict'].keys()
    return channel.id in raid_channels

def check_eggchannel(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    type = ctx.bot.guild_dict[guild.id].get('raidchannel_dict',{}).get(channel.id,{}).get('type',None)
    return type == 'egg'

def check_raidactive(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    return ctx.bot.guild_dict[guild.id].get('raidchannel_dict',{}).get(channel.id,{}).get('active',False)

def check_exraidset(ctx):
    if ctx.guild is None:
        return False
    guild = ctx.guild
    return ctx.bot.guild_dict[guild.id]['configure_dict']['exraid'].get('enabled',False)

def check_exraidreport(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    channel_list = [x for x in ctx.bot.guild_dict[guild.id]['configure_dict']['exraid'].get('report_channels',{}).keys()]
    return channel.id in channel_list

def check_inviteset(ctx):
    if ctx.guild is None:
        return False
    guild = ctx.guild
    return ctx.bot.guild_dict[guild.id]['configure_dict']['invite'].get('enabled',False)

def check_exraidchannel(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    level = ctx.bot.guild_dict[guild.id].get('raidchannel_dict',{}).get(channel.id,{}).get('egglevel',False)
    type =  ctx.bot.guild_dict[guild.id].get('raidchannel_dict',{}).get(channel.id,{}).get('type',False)
    return (level == 'EX') or (type == 'exraid')

def check_meetupset(ctx):
    if ctx.guild is None:
        return False
    guild = ctx.guild
    if not ctx.bot.guild_dict[guild.id]['configure_dict'].get('meetup'):
        return False
    return ctx.bot.guild_dict[guild.id]['configure_dict']['meetup'].get('enabled',False)

def check_meetupreport(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    if not ctx.bot.guild_dict[guild.id]['configure_dict'].get('meetup'):
        return False
    channel_list = [x for x in ctx.bot.guild_dict[guild.id]['configure_dict']['meetup'].get('report_channels',{}).keys()]
    return channel.id in channel_list

def check_meetupchannel(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    meetup =  ctx.bot.guild_dict[guild.id].get('raidchannel_dict',{}).get(channel.id,{}).get('meetup',False)
    return meetup

def check_tradeset(ctx):
    if ctx.guild is None:
        return False
    guild = ctx.guild
    return ctx.bot.guild_dict[guild.id]['configure_dict'].setdefault('trade', {}).get('enabled', False)

def check_tradereport(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    channel_list = [x for x in ctx.bot.guild_dict[guild.id]['configure_dict'].setdefault('trade', {}).get('report_channels',[])]
    return channel.id in channel_list

def check_wildset(ctx):
    if ctx.guild is None:
        return False
    guild = ctx.guild
    return ctx.bot.guild_dict[guild.id]['configure_dict']['wild'].get('enabled',False)

def check_wildreport(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    channel_list = [x for x in ctx.bot.guild_dict[guild.id]['configure_dict']['wild'].get('report_channels',{}).keys()]
    return channel.id in channel_list

def check_lureset(ctx):
    if ctx.guild is None:
        return False
    guild = ctx.guild
    return ctx.bot.guild_dict[guild.id]['configure_dict']['lure'].get('enabled',False)

def check_lurereport(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    channel_list = [x for x in ctx.bot.guild_dict[guild.id]['configure_dict']['lure'].get('report_channels',{}).keys()]
    return channel.id in channel_list

def check_teamset(ctx):
    if ctx.guild is None:
        return False
    guild = ctx.guild
    return ctx.bot.guild_dict[guild.id]['configure_dict']['team'].get('enabled',False)

def check_welcomeset(ctx):
    if ctx.guild is None:
        return False
    guild = ctx.guild
    return ctx.bot.guild_dict[guild.id]['configure_dict']['welcome'].get('enabled',False)

def check_regionsset(ctx):
    if ctx.guild is None:
        return False
    guild = ctx.guild
    return ctx.bot.guild_dict[guild.id]['configure_dict'].setdefault('regions', {}).get('enabled', False)

def check_regionchange(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    channel_list = ctx.bot.guild_dict[guild.id]['configure_dict']['regions'].get('command_channels',[])
    return channel.id in channel_list

def check_archiveset(ctx):
    if ctx.guild is None:
        return False
    guild = ctx.guild
    return ctx.bot.guild_dict[guild.id]['configure_dict']['archive'].get('enabled',False)

def check_researchset(ctx):
    if ctx.guild is None:
        return False
    guild = ctx.guild
    return ctx.bot.guild_dict[guild.id]['configure_dict']['research'].get('enabled',False)

def check_researchreport(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    channel_list = [x for x in ctx.bot.guild_dict[guild.id]['configure_dict']['research'].get('report_channels',{}).keys()]
    return channel.id in channel_list

def check_adminchannel(ctx):
    if ctx.guild is None:
        return False
    channel = ctx.channel
    guild = ctx.guild
    channel_list = [x for x in ctx.bot.guild_dict[guild.id]['configure_dict'].get('admin',{}).get('command_channels',[])]
    return channel.id in channel_list

#Decorators
def allowreports():
    def predicate(ctx):
        if check_raidreport(ctx) or (check_eggchannel(ctx) and check_raidchannel(ctx)):
            return True
        elif check_exraidreport(ctx) or check_exraidchannel(ctx):
            return True
        elif check_wildreport(ctx):
            return True
        elif check_researchreport(ctx):
            return True
        else:
            raise errors.ReportCheckFail()
    return commands.check(predicate)

def allowraidreport():
    def predicate(ctx):
        if check_raidset(ctx):
            if check_raidreport(ctx) or (check_eggchannel(ctx) and check_raidchannel(ctx)):
                return True
            else:
                raise errors.RegionEggChannelCheckFail()
        else:
            raise errors.RaidSetCheckFail()
    return commands.check(predicate)

def allowexraidreport():
    def predicate(ctx):
        if check_exraidset(ctx):
            if check_exraidreport(ctx) or check_exraidchannel(ctx):
                return True
            else:
                raise errors.RegionExRaidChannelCheckFail()
        else:
            raise errors.EXRaidSetCheckFail()
    return commands.check(predicate)

def allowwildreport():
    def predicate(ctx):
        if check_wildset(ctx):
            if check_wildreport(ctx):
                return True
            else:
                raise errors.WildReportChannelCheckFail()
        else:
            raise errors.WildSetCheckFail()
    return commands.check(predicate)


def allowlurereport():
    def predicate(ctx):
        if check_lureset(ctx):
            if check_lurereport(ctx):
                return True
            else:
                raise errors.LureReportChannelCheckFail()
        else:
            raise errors.LureSetCheckFail()
    return commands.check(predicate)

def allowresearchreport():
    def predicate(ctx):
        if check_researchset(ctx):
            if check_researchreport(ctx) or check_adminchannel(ctx):
                return True
            else:
                raise errors.ResearchReportChannelCheckFail()
        else:
            raise errors.ResearchSetCheckFail()
    return commands.check(predicate)

def allowmeetupreport():
    def predicate(ctx):
        if check_meetupset(ctx):
            if check_meetupreport(ctx):
                return True
            else:
                raise errors.MeetupReportChannelCheckFail()
        else:
            raise errors.MeetupSetCheckFail()
    return commands.check(predicate)

def allowinvite():
    def predicate(ctx):
        if check_inviteset(ctx):
            if check_citychannel(ctx):
                return True
            else:
                raise errors.CityChannelCheckFail()
        else:
            raise errors.InviteSetCheckFail()
    return commands.check(predicate)

def allowteam():
    def predicate(ctx):
        if check_teamset(ctx):
            if not check_raidchannel(ctx):
                return True
            else:
                raise errors.NonRaidChannelCheckFail()
        else:
            raise errors.TeamSetCheckFail()
    return commands.check(predicate)

def allowsubscription():
    def predicate(ctx):
        if check_subscriptionset(ctx):
            if check_subscriptionchannel(ctx):
                return True
            else:
                raise errors.SubscriptionChannelCheckFail()
        raise errors.SubscriptionSetCheckFail()
    return commands.check(predicate) 

def allowpvp():
    def predicate(ctx):
        if check_pvpset(ctx):
            if check_pvpchannel(ctx):
                return True
            else:
                raise errors.PvpChannelCheckFail()
        raise errors.PvpSetCheckFail()
    return commands.check(predicate) 

def allowjoin():
    def predicate(ctx):
        if check_joinset(ctx):
            return True
        raise errors.JoinSetCheckFail()
    return commands.check(predicate) 

def allowregion():
    def predicate(ctx):
        if check_regionsset(ctx):
            if check_regionchange(ctx):
                return True
            else:
                raise errors.RegionChangeCheckFail()
        else:
            raise errors.RegionsSetCheckFail()
    return commands.check(predicate)
            

def allowtrade():
    def predicate(ctx):
        if check_tradeset(ctx):
            if check_tradereport(ctx):
                return True
            else:
                raise errors.TradeChannelCheckFail()
        else:
            raise errors.TradeSetCheckFail()
    return commands.check(predicate)

def allowarchive():
    def predicate(ctx):
        if check_archiveset(ctx):
            if check_raidchannel(ctx):
                return True
        raise errors.ArchiveSetCheckFail()
    return commands.check(predicate)

def citychannel():
    def predicate(ctx):
        if check_citychannel(ctx):
            return True
        raise errors.CityChannelCheckFail()
    return commands.check(predicate)

def good_standing():
    def predicate(ctx):
        if is_good_standing(ctx):
            return True
        raise errors.UserBanned()
    return commands.check(predicate)

def raidchannel():
    def predicate(ctx):
        if check_raidchannel(ctx):
            return True
        raise errors.RaidChannelCheckFail()
    return commands.check(predicate)

def exraidchannel():
    def predicate(ctx):
        if check_exraidchannel(ctx):
            return True
        raise errors.ExRaidChannelCheckFail()
    return commands.check(predicate)

def nonraidchannel():
    def predicate(ctx):
        if (not check_raidchannel(ctx)):
            return True
        raise errors.NonRaidChannelCheckFail()
    return commands.check(predicate)

def activeraidchannel():
    def predicate(ctx):
        if check_raidchannel(ctx) and not check_meetupchannel(ctx):
            if check_raidactive(ctx):
                return True
        raise errors.ActiveRaidChannelCheckFail()
    return commands.check(predicate)

def activechannel():
    def predicate(ctx):
        if check_raidchannel(ctx):
            if check_raidactive(ctx):
                return True
        raise errors.ActiveChannelCheckFail()
    return commands.check(predicate)

def feature_enabled(names, ensure_all=False):
    def predicate(ctx):
        cfg = ctx.bot.guild_dict[ctx.guild.id]['configure_dict']
        enabled = [k for k, v in cfg.items() if v.get('enabled', False)]
        if isinstance(names, list):
            result = [n in enabled for n in names]
            return all(*result) if ensure_all else any(*result)
        if isinstance(names, str):
            return names in enabled
    return commands.check(predicate)
