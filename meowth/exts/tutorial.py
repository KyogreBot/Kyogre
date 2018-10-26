import asyncio

import discord
from discord.ext import commands


from meowth import utils
from meowth import checks

class Tutorial:
    def __init__(self, bot):
        self.bot = bot

    async def wait_for_cmd(self, tutorial_channel, newbie, command_name):
        # build check relevant to command
        def check(c):
            if not c.channel == tutorial_channel:
                return False
            if not c.author == newbie:
                return False
            if c.command.name == command_name:
                return True
            return False

        # wait for the command to complete
        cmd_ctx = await self.bot.wait_for(
            'command_completion', check=check, timeout=300)

        return cmd_ctx

    def get_overwrites(self, guild, member):
        return {
            guild.default_role: discord.PermissionOverwrite(
                read_messages=False),
            member: discord.PermissionOverwrite(
                read_messages=True,
                send_messages=True,
                manage_channels=True),
            guild.me: discord.PermissionOverwrite(
                read_messages=True)
            }

    async def sub_tutorial(self, ctx, config):
        report_channels = config['subscriptions']['report_channels']
        report_channels.append(ctx.tutorial_channel.id)

        await ctx.tutorial_channel.send(
            "Using Kyogre bot, you can *subscribe* for push notifications "
            "when someone reports wild Pokemon spawns, particular raid bosses, "
            "or research encounters that you're interested!\n"
            f"The **{ctx.prefix}sub add** command adds a subscription.\n"
            f"Try it out now, use the **{ctx.prefix}sub** command "
            "followed by one of these options `wild, raid, research` "
            "and then the name of the Pokemon you want\n"
            f"Ex: `{ctx.prefix}sub add raid machamp`")

        try:
            await self.wait_for_cmd(ctx.tutorial_channel, ctx.author, 'add')

            # acknowledge and wait a second before continuing
            await ctx.tutorial_channel.send("Great job!")
            await asyncio.sleep(2)

        # if no response for 5 minutes, close tutorial
        except asyncio.TimeoutError:
            await ctx.tutorial_channel.send(
                f"You took too long to complete the **{ctx.prefix}sub add** "
                "command! This channel will be deleted in ten seconds.")
            await asyncio.sleep(10)
            await ctx.tutorial_channel.delete()

            return False

        await ctx.tutorial_channel.send(
            "You can check what you've subscribed to at any time "
            f"using **{ctx.prefix}sub list** and you will receive "
            "a message listing all of your subscriptions\n"
            "If you only want to see subscriptions of a particular "
            "type you can specify that type as well.\n"
            f"For example: **{ctx.prefix}sub list raid**\n"
            f"Or: **{ctx.prefix}sub list raid, research**\n"
            "Give it a try now!")

        try:
            await self.wait_for_cmd(ctx.tutorial_channel, ctx.author, 'list')

            # acknowledge and wait a second before continuing
            await ctx.tutorial_channel.send("Great job!")
            await asyncio.sleep(2)

        # if no response for 5 minutes, close tutorial
        except asyncio.TimeoutError:
            await ctx.tutorial_channel.send(
                f"You took too long to complete the **{ctx.prefix}sub list** "
                "command! This channel will be deleted in ten seconds.")
            await asyncio.sleep(10)
            await ctx.tutorial_channel.delete()

            return False

        await ctx.tutorial_channel.send(
            "If you no longer wish to receive notifications for a "
            "particular subscription, you can remove it using "
            f"**{ctx.prefix}sub remove** along with the type "
            "and Pokemon name, just like when you added it.\n"
            f"For example: `{ctx.prefix}sub remove raid machamp`\n"
            "Give it a try now!")

        try:
            await self.wait_for_cmd(ctx.tutorial_channel, ctx.author, 'remove')

            # acknowledge and wait a second before continuing
            await ctx.tutorial_channel.send("Great job!")
            await asyncio.sleep(2)

        # if no response for 5 minutes, close tutorial
        except asyncio.TimeoutError:
            await ctx.tutorial_channel.send(
                f"You took too long to complete the **{ctx.prefix}sub remove** "
                "command! This channel will be deleted in ten seconds.")
            await asyncio.sleep(10)
            await ctx.tutorial_channel.delete()

            return False

        # clean up by removing tutorial from report channel config
        finally:
            report_channels.remove(ctx.tutorial_channel.id)

        await ctx.tutorial_channel.send(
            "Now you know all about how to subscribe to notifications "
            "for the Pokemon you want! Here's a quick recap:\n"
            f"Use **{ctx.prefix}sub add** to add a new subscription\n"
            f"Use **{ctx.prefix}sub remove** to remove a subscription\n"
            f"Use **{ctx.prefix}sub list** to see your subscriptions\n"
            "Available subscription types are:\n"
            "`raid, research, wild, pokemon` (the last one covers "
            "pokemon reported in any of the other ways)\n"
            "You can see all of the options for this command by "
            f"using **{ctx.prefix}help subscribe**")
        await asyncio.sleep(10)

        return True

    async def wild_tutorial(self, ctx, config):
        report_channels = config['wild']['report_channels']
        report_channels[ctx.tutorial_channel.id] = 'test'

        await ctx.tutorial_channel.send(
            "When you come across a rare spawn in the wild, "
            f"use the **{ctx.prefix}wild** command to report it! "
            "If the spawn is near a Pokestop or Gym, provide the name. "
            "Otherwise provide a map pin if possible or the most "
            "accurate description you can of the location. The bot will "
            "send a message summarizing the report and containing a link "
            "to the spawn location. Your report must contain the name of "
            "the Pokemon followed by its location. \n"
            "Try reporting a wild spawn!\n"
            f"Ex: `{ctx.prefix}wild magikarp some park`")

        try:
            await self.wait_for_cmd(ctx.tutorial_channel, ctx.author, 'wild')

            # acknowledge and wait a second before continuing
            await ctx.tutorial_channel.send("Great job!")
            await asyncio.sleep(1)

        # if no response for 5 minutes, close tutorial
        except asyncio.TimeoutError:
            await ctx.tutorial_channel.send(
                f"You took too long to complete the **{ctx.prefix}wild** "
                "command! This channel will be deleted in ten seconds.")
            await asyncio.sleep(10)
            await ctx.tutorial_channel.delete()
            return False

        # clean up by removing tutorial from report channel config
        finally:
            del report_channels[ctx.tutorial_channel.id]

        return True

    async def raid_tutorial(self, ctx, config):
        report_channels = config['raid']['report_channels']
        category_dict = config['raid']['category_dict']
        tutorial_channel = ctx.tutorial_channel
        prefix = ctx.prefix
        raid_channel = None

        # add tutorial channel to valid want report channels
        report_channels[tutorial_channel.id] = 'test'

        if config['raid']['categories'] == "region":
            category_dict[tutorial_channel.id] = tutorial_channel.category_id

        async def timeout_raid(cmd):
            await tutorial_channel.send(
                f"You took too long to complete the **{prefix}{cmd}** "
                "command! This channel will be deleted in ten seconds.")
            await asyncio.sleep(10)
            await tutorial_channel.delete()
            del report_channels[tutorial_channel.id]
            del category_dict[tutorial_channel.id]
            if raid_channel:
                await raid_channel.delete()
                ctx.bot.loop.create_task(self.bot.expire_channel(raid_channel))
            return

        await tutorial_channel.send(
            "When you spot a raid, you can report it to Kyogre using "
            f"the **{prefix}raid** command! When you make a report, "
            "Kyogre sends a message summarizing the report and creates "
            "a text channel for coordination. Kyogre also maintains a "
            "list of all currently active raids.\n"
            "Your report must contain, in this order: The Pokemon (if an "
            "active raid) or raid level (if an egg), and the location;\n"
            "the report may optionally contain the weather (see "
            f"**{prefix}help weather** for accepted options) and the "
            "minutes remaining until hatch or expiry (at the end of the "
            "report) \n\n"
            "Try reporting a raid!\n"
            f"Ex: `{prefix}raid magikarp local church cloudy 42`\n"
            f"`{prefix}raid machamp local park`"
            f"`{prefix}raid 3 local church 27`")

        try:
            while True:
                raid_ctx = await self.wait_for_cmd(
                    tutorial_channel, ctx.author, 'raid')

                # get the generated raid channel
                raid_channel = raid_ctx.raid_channel

                if raid_channel:
                    break

                # acknowledge failure and redo wait_for
                await tutorial_channel.send(
                    "Doesn't look like it worked. Make sure you're not "
                    "missing any arguments from your raid command and "
                    "try again.")

            # acknowledge and redirect to new raid channel
            await tutorial_channel.send(
                "Great job! Let's head into the new raid channel you just "
                f"created: {raid_channel.mention}")
            await asyncio.sleep(1)

        # if no response for 5 minutes, close tutorial
        except asyncio.TimeoutError:
            await timeout_raid('raid')
            return False

        # post raid help info prefix, avatar, user
        helpembed = await utils.get_raid_help(
            ctx.prefix, ctx.bot.user.avatar_url)

        await raid_channel.send(
            f"This is an example of a raid channel. Here is a list of "
            "commands that can be used in here:", embed=helpembed)

        await raid_channel.send(
            f"Try expressing interest in this raid!\n\n"
            f"Ex: `{prefix}interested 5 m3 i1 v1` would mean 5 trainers: "
            "3 Mystic, 1 Instinct, 1 Valor")

        # wait for interested status update
        try:
            await self.wait_for_cmd(
                raid_channel, ctx.author, 'interested')

        # if no response for 5 minutes, close tutorial
        except asyncio.TimeoutError:
            await timeout_raid('interested')
            return False

        # acknowledge and continue with pauses between
        await asyncio.sleep(1)
        await raid_channel.send(
            f"Great job! To save time, you can also use **{prefix}i** "
            f"as an alias for **{prefix}interested**.")

        await asyncio.sleep(1)
        await raid_channel.send(
            "Now try letting people know that you are on your way!\n\n"
            f"Ex: `{prefix}coming`")

        # wait for coming status update
        try:
            await self.wait_for_cmd(
                raid_channel, ctx.author, 'coming')

        # if no response for 5 minutes, close tutorial
        except asyncio.TimeoutError:
            await timeout_raid('coming')
            return False

        # acknowledge and continue with pauses between
        await asyncio.sleep(1)
        await raid_channel.send(
            "Great! Note that if you have already specified your party "
            "in a previous command, you do not have to again for the "
            "current raid unless you are changing it. Also, "
            f"**{prefix}c** is an alias for **{prefix}coming**.")

        await asyncio.sleep(1)
        await raid_channel.send(
            "Now try letting people know that you have arrived at the "
            "raid!\n\n"
            f"Ex: `{prefix}here`")

        # wait for here status update
        try:
            await self.wait_for_cmd(
                raid_channel, ctx.author, 'here')

        # if no response for 5 minutes, close tutorial
        except asyncio.TimeoutError:
            await timeout_raid('here')
            return False

        # acknowledge and continue with pauses between
        await asyncio.sleep(1)
        await raid_channel.send(
            f"Good! Please note that **{prefix}h** is an alias for "
            f"**{prefix}here**")

        await asyncio.sleep(1)
        await raid_channel.send(
            "Now try checking to see everyone's RSVP status for this "
            f"raid!\n\nEx: `{prefix}list`")

        # wait for list command completion
        try:
            await self.wait_for_cmd(
                raid_channel, ctx.author, 'list')

        # if no response for 5 minutes, close tutorial
        except asyncio.TimeoutError:
            await timeout_raid('list')
            return False

        # acknowledge and continue with pauses between
        await asyncio.sleep(1)
        await raid_channel.send(
            "Awesome! Since no one else is on their way, try using the "
            f"**{prefix}starting** command to move everyone on the "
            "'here' list to a lobby!")

        # wait for starting command completion
        try:
            await self.wait_for_cmd(
                raid_channel, ctx.author, 'starting')

        # if no response for 5 minutes, close tutorial
        except asyncio.TimeoutError:
            await timeout_raid('starting')
            return False

        # acknowledge and continue with pauses between
        await asyncio.sleep(1)
        await raid_channel.send(
            f"Great! You are now listed as being 'in the lobby', where "
            "you will remain for two minutes until the raid begins. In "
            "that time, anyone can request a backout with the "
            f"**{prefix}backout** command. If the person requesting is "
            "in the lobby, the backout is automatic. If it is someone "
            "who arrived at the raid afterward, confirmation will be "
            "requested from a lobby member. When a backout is confirmed, "
            "all members will be returned to the 'here' list.")

        await asyncio.sleep(1)
        await raid_channel.send(
            "A couple of notes about raid channels. Kyogre has "
            "partnered with Pokebattler to give you the best counters "
            "for each raid boss in every situation. You can set the "
            "weather in the initial raid report, or with the "
            f"**{prefix}weather** command. You can select the moveset "
            "using the reactions in the initial counters message. If "
            f"you have a Pokebattler account, you can use **{prefix}set "
            "pokebattler <id>** to link them! After that, the "
            f"**{prefix}counters**  command will DM you your own counters "
            "pulled from your Pokebox.")

        await asyncio.sleep(1)
        await raid_channel.send(
            "Last thing: if you need to update the expiry time, use "
            f"**{prefix}timerset <minutes left>**\n\n"
            "Feel free to play around with the commands here for a while. "
            f"When you're finished, type `{prefix}timerset 0` and the "
            "raid will expire.")

        # wait for timerset command completion
        try:
            await self.wait_for_cmd(
                raid_channel, ctx.author, 'timerset')

        # if no response for 5 minutes, close tutorial
        except asyncio.TimeoutError:
            await timeout_raid('timerset')
            return False

        # acknowledge and direct member back to tutorial channel
        await raid_channel.send(
            f"Great! Now return to {tutorial_channel.mention} to "
            "continue the tutorial. This channel will be deleted in "
            "ten seconds.")

        await tutorial_channel.send(
            f"Hey {ctx.author.mention}, once I'm done cleaning up the "
            "raid channel, the tutorial will continue here!")

        await asyncio.sleep(10)

        # remove tutorial raid channel
        await raid_channel.delete()
        raid_channel = None
        del report_channels[tutorial_channel.id]

        return True

    async def research_tutorial(self, ctx, config):
        report_channels = config['research']['report_channels']
        report_channels[ctx.tutorial_channel.id] = 'test'

        await ctx.tutorial_channel.send(
            "When you find a useful research task, you can report it "
            f"using the **{ctx.prefix}research** command! "
            "There are two ways to use this command:\n"
            f"**{ctx.prefix}research** will start an interactive "
            "session where the bot prompts you for the task and location "
            "of the research task.\n Or you can use "
            f"**{ctx.prefix}research <pokestop>, <task>** to "
            "submit the report all at once.\n\n"
            f"Try it out by typing `{ctx.prefix}research`")

        # wait for research command completion
        try:
            await self.wait_for_cmd(
                ctx.tutorial_channel, ctx.author, 'research')

            # acknowledge and wait a second before continuing
            await ctx.tutorial_channel.send("Great job!")
            await asyncio.sleep(1)

        # if no response for 5 minutes, close tutorial
        except asyncio.TimeoutError:
            await ctx.tutorial_channel.send(
                f"You took too long to use the **{ctx.prefix}research** "
                "command! This channel will be deleted in ten seconds.")
            await asyncio.sleep(10)
            await ctx.tutorial_channel.delete()
            return False

        # clean up by removing tutorial from report channel config
        finally:
            del report_channels[ctx.tutorial_channel.id]

        return True

    async def team_tutorial(self, ctx):
        await ctx.tutorial_channel.send(
            f"This server uses the **{ctx.prefix}team** command to "
            "allow members to select which Pokemon Go team they belong "
            f"to! Type `{ctx.prefix}team mystic` for example if you are in "
            "Team Mystic.")

        # wait for team command completion
        try:
            await self.wait_for_cmd(
                ctx.tutorial_channel, ctx.author, 'team')

            # acknowledge and wait a second before continuing
            await ctx.tutorial_channel.send("Great job!")
            await asyncio.sleep(1)

        # if no response for 5 minutes, close tutorial
        except asyncio.TimeoutError:
            await ctx.tutorial_channel.send(
                f"You took too long to use the **{ctx.prefix}team** command! "
                "This channel will be deleted in ten seconds.")
            await asyncio.sleep(10)
            await ctx.tutorial_channel.delete()
            return False

        return True

    async def region_tutorial(self, ctx, config):
        report_channels = config['regions']['command_channels']
        report_channels.append(ctx.tutorial_channel.id)
        await ctx.tutorial_channel.send(
            f"On this server you can use the **{ctx.prefix}region** command to "
            f"join and leave regions. Use **{ctx.prefix}region join** to list "
            "the regions available to join"
            "Try it now:\n"
            f"`{ctx.prefix}region join `")

        try:
            await self.wait_for_cmd(
                ctx.tutorial_channel, ctx.author, 'join')
            # acknowledge and wait a second before continuing
            await ctx.tutorial_channel.send("Great job!")
            await asyncio.sleep(1)
        except asyncio.TimeoutError:
            await ctx.tutorial_channel.send(
                f"You took too long to use the **{ctx.prefix}region join** command! "
                "This channel will be deleted in ten seconds.")
            await asyncio.sleep(10)
            report_channels.remove(ctx.tutorial_channel.id)
            await ctx.tutorial_channel.delete()
            return False

        await ctx.tutorial_channel.send(
            f"Once you've chosen a region to join, use **{ctx.prefix}region join** <region> "
            "to join.\n "
            "Try it now:\n"
            f"`{ctx.prefix}region join renton`")

        try:
            await self.wait_for_cmd(
                ctx.tutorial_channel, ctx.author, 'join')

            # acknowledge and wait a second before continuing
            await ctx.tutorial_channel.send("Great job!")
            await asyncio.sleep(1)
        except asyncio.TimeoutError:
            await ctx.tutorial_channel.send(
                f"You took too long to use the **{ctx.prefix}region join** command! "
                "This channel will be deleted in ten seconds.")
            await asyncio.sleep(10)
            report_channels.remove(ctx.tutorial_channel.id)
            await ctx.tutorial_channel.delete()
            return False

        await ctx.tutorial_channel.send(
            f"If you ever decide to leave a region, use **{ctx.prefix}region leave** <region> "
            "to join.\n "
            "Try it now:\n"
            f"`{ctx.prefix}region leave renton`")

        try:
            await self.wait_for_cmd(
                ctx.tutorial_channel, ctx.author, 'leave')

            # acknowledge and wait a second before continuing
            await ctx.tutorial_channel.send("Great job!")
            await asyncio.sleep(1)
        # if no response for 5 minutes, close tutorial
        except asyncio.TimeoutError:
            await ctx.tutorial_channel.send(
                f"You took too long to use the **{ctx.prefix}region leave** command! "
                "This channel will be deleted in ten seconds.")
            await asyncio.sleep(10)
            report_channels.remove(ctx.tutorial_channel.id)
            await ctx.tutorial_channel.delete()
            return False

        report_channels.remove(ctx.tutorial_channel.id)
        return True

    @commands.group(invoke_without_command=True)
    async def tutorial(self, ctx):
        """Launches an interactive tutorial session for Kyogre.

        Kyogre will create a private channel and initiate a
        conversation that walks you through the various commands
        that are enabled on the current server."""

        newbie = ctx.author
        guild = ctx.guild
        prefix = ctx.prefix

        # get channel overwrites
        ows = self.get_overwrites(guild, newbie)

        # create tutorial channel
        name = utils.sanitize_channel_name(newbie.display_name+"-tutorial")
        ctx.tutorial_channel = await guild.create_text_channel(
            name, overwrites=ows)
        await ctx.message.delete()
        await ctx.send(
            ("I've created a private tutorial channel for "
             f"you! Continue in {ctx.tutorial_channel.mention}"),
            delete_after=20.0)

        # get tutorial settings
        cfg = self.bot.guild_dict[guild.id]['configure_dict']
        enabled = [k for k, v in cfg.items() if v.get('enabled', False)]

        await ctx.tutorial_channel.send(
            f"Hi {ctx.author.mention}! I'm Kyogre, a Discord helper bot for "
            "Pokemon Go communities! I created this channel to teach you all "
            "about the things I can do to help you on this server! You can "
            "abandon this tutorial at any time and I'll delete this channel "
            "after five minutes. Let's get started!")

        try:

            # start region tutorial
            if 'regions' in enabled:
                completed = await self.region_tutorial(ctx, cfg)
                if not completed:
                    return

            # start subscription tutorial
            if 'subscriptions' in enabled:
                completed = await self.sub_tutorial(ctx, cfg)
                if not completed:
                    return

            # start wild tutorial
            if 'wild' in enabled:
                completed = await self.wild_tutorial(ctx, cfg)
                if not completed:
                    return

            # start raid
            if 'raid' in enabled:
                completed = await self.raid_tutorial(ctx, cfg)
                if not completed:
                    return

            # start exraid
            if 'exraid' in enabled:
                invitestr = ""

                if 'invite' in enabled:
                    invitestr = (
                        "The text channels that are created with this command "
                        f"are read-only until members use the **{prefix}invite** "
                        "command.")

                await ctx.tutorial_channel.send(
                    f"This server utilizes the **{prefix}exraid** command to "
                    "report EX raids! When you use it, I will send a message "
                    "summarizing the report and create a text channel for "
                    f"coordination. {invitestr}\n"
                    "The report must contain only the location of the EX raid.\n\n"
                    "Due to the longer-term nature of EX raid channels, we won't "
                    "try this command out right now.")

            # start research
            if 'research' in enabled:
                completed = await self.research_tutorial(ctx, cfg)
                if not completed:
                    return

            # start team
            # if 'team' in enabled:
            #     completed = await self.team_tutorial(ctx)
            #     if not completed:
            #         return

            # finish tutorial
            await ctx.tutorial_channel.send(
                f"This concludes the Kyogre tutorial! "
                "This channel will be deleted in 30 seconds.")
            await asyncio.sleep(30)

        finally:
            await ctx.tutorial_channel.delete()

    @tutorial.command()
    @checks.feature_enabled('subscriptions')
    async def sub(self, ctx):
        """Launches a tutorial session for the subscription feature.

        Kyogre will create a private channel and initiate a
        conversation that walks you through the various commands
        that are enabled on the current server."""

        newbie = ctx.author
        guild = ctx.guild

        # get channel overwrites
        ows = self.get_overwrites(guild, newbie)

        # create tutorial channel
        name = utils.sanitize_channel_name(newbie.display_name+"-tutorial")
        ctx.tutorial_channel = await guild.create_text_channel(
            name, overwrites=ows)
        await ctx.message.delete()
        await ctx.send(
            ("I've created a private tutorial channel for "
             f"you! Continue in {ctx.tutorial_channel.mention}"),
            delete_after=20.0)

        # get tutorial settings
        cfg = self.bot.guild_dict[guild.id]['configure_dict']

        await ctx.tutorial_channel.send(
            f"Hi {ctx.author.mention}! I'm Kyogre, a Discord helper bot for "
            "Pokemon Go communities! I created this channel to teach you "
            "about the want command! You can abandon this tutorial at any time "
            "and I'll delete this channel after five minutes. "
            "Let's get started!")

        try:
            await self.sub_tutorial(ctx, cfg)
            await ctx.tutorial_channel.send(
                f"This concludes the Kyogre tutorial! "
                "This channel will be deleted in ten seconds.")
            await asyncio.sleep(10)
        finally:
            await ctx.tutorial_channel.delete()

    @tutorial.command()
    @checks.feature_enabled('wild')
    async def wild(self, ctx):
        """Launches a tutorial session for the wild feature.

        Kyogre will create a private channel and initiate a
        conversation that walks you through wild command."""

        newbie = ctx.author
        guild = ctx.guild

        # get channel overwrites
        ows = self.get_overwrites(guild, newbie)

        # create tutorial channel
        name = utils.sanitize_channel_name(newbie.display_name+"-tutorial")
        ctx.tutorial_channel = await guild.create_text_channel(
            name, overwrites=ows)
        await ctx.message.delete()
        await ctx.send(
            ("I've created a private tutorial channel for "
             f"you! Continue in {ctx.tutorial_channel.mention}"),
            delete_after=20.0)

        # get tutorial settings
        cfg = self.bot.guild_dict[guild.id]['configure_dict']

        await ctx.tutorial_channel.send(
            f"Hi {ctx.author.mention}! I'm Kyogre, a Discord helper bot for "
            "Pokemon Go communities! I created this channel to teach you "
            "about the wild command! You can abandon this tutorial at any time "
            "and I'll delete this channel after five minutes. "
            "Let's get started!")

        try:
            await self.wild_tutorial(ctx, cfg)
            await ctx.tutorial_channel.send(
                f"This concludes the tutorial! "
                "This channel will be deleted in ten seconds.")
            await asyncio.sleep(10)
        finally:
            await ctx.tutorial_channel.delete()

    @tutorial.command()
    @checks.feature_enabled('raid')
    async def raid(self, ctx):
        """Launches a tutorial session for the raid feature.

        Kyogre will create a private channel and initiate a
        conversation that walks you through the raid commands."""

        newbie = ctx.author
        guild = ctx.guild

        # get channel overwrites
        ows = self.get_overwrites(guild, newbie)

        # create tutorial channel
        name = utils.sanitize_channel_name(newbie.display_name+"-tutorial")
        ctx.tutorial_channel = await guild.create_text_channel(
            name, overwrites=ows)
        await ctx.message.delete()
        await ctx.send(
            ("I've created a private tutorial channel for "
             f"you! Continue in {ctx.tutorial_channel.mention}"),
            delete_after=20.0)

        # get tutorial settings
        cfg = self.bot.guild_dict[guild.id]['configure_dict']

        await ctx.tutorial_channel.send(
            f"Hi {ctx.author.mention}! I'm Kyogre, a Discord helper bot for "
            "Pokemon Go communities! I created this channel to teach you "
            "about the raid command! You can abandon this tutorial at any time "
            "and I'll delete this channel after five minutes. "
            "Let's get started!")

        try:
            await self.raid_tutorial(ctx, cfg)
            await ctx.tutorial_channel.send(
                f"This concludes the tutorial! "
                "This channel will be deleted in ten seconds.")
            await asyncio.sleep(10)
        finally:
            await ctx.tutorial_channel.delete()

    @tutorial.command()
    @checks.feature_enabled('research')
    async def research(self, ctx):
        """Launches a tutorial session for the research feature.

        Kyogre will create a private channel and initiate a
        conversation that walks you through the research command."""

        newbie = ctx.author
        guild = ctx.guild

        # get channel overwrites
        ows = self.get_overwrites(guild, newbie)

        # create tutorial channel
        name = utils.sanitize_channel_name(newbie.display_name+"-tutorial")
        ctx.tutorial_channel = await guild.create_text_channel(
            name, overwrites=ows)
        await ctx.message.delete()
        await ctx.send(
            ("I've created a private tutorial channel for "
             f"you! Continue in {ctx.tutorial_channel.mention}"),
            delete_after=20.0)

        # get tutorial settings
        cfg = self.bot.guild_dict[guild.id]['configure_dict']

        await ctx.tutorial_channel.send(
            f"Hi {ctx.author.mention}! I'm Kyogre, a Discord helper bot for "
            "Pokemon Go communities! I created this channel to teach you "
            "about the research command! You can abandon this tutorial at "
            "any time and I'll delete this channel after five minutes. "
            "Let's get started!")

        try:
            await self.research_tutorial(ctx, cfg)
            await ctx.tutorial_channel.send(
                f"This concludes the tutorial! "
                "This channel will be deleted in ten seconds.")
            await asyncio.sleep(10)
        finally:
            await ctx.tutorial_channel.delete()

    @tutorial.command()
    @checks.feature_enabled('team')
    async def team(self, ctx):
        """Launches a tutorial session for the team feature.

        Kyogre will create a private channel and initiate a
        conversation that walks you through the team command."""

        newbie = ctx.author
        guild = ctx.guild

        # get channel overwrites
        ows = self.get_overwrites(guild, newbie)

        # create tutorial channel
        name = utils.sanitize_channel_name(newbie.display_name+"-tutorial")
        ctx.tutorial_channel = await guild.create_text_channel(
            name, overwrites=ows)
        await ctx.message.delete()
        await ctx.send(
            ("I've created a private tutorial channel for "
             f"you! Continue in {ctx.tutorial_channel.mention}"),
            delete_after=20.0)

        await ctx.tutorial_channel.send(
            f"Hi {ctx.author.mention}! I'm Kyogre, a Discord helper bot for "
            "Pokemon Go communities! I created this channel to teach you "
            "about the team command! You can abandon this tutorial at any time "
            "and I'll delete this channel after five minutes. "
            "Let's get started!")

        try:
            await self.team_tutorial(ctx)
            await ctx.tutorial_channel.send(
                f"This concludes the tutorial! "
                "This channel will be deleted in ten seconds.")
            await asyncio.sleep(10)
        finally:
            await ctx.tutorial_channel.delete()

def setup(bot):
    bot.add_cog(Tutorial(bot))
