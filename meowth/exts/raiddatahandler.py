import json
import re
from discord.ext import commands
from meowth import utils
from meowth import checks
from meowth.exts.pokemon import Pokemon

class RaidDataHandler(commands.Cog):
    """Raid Data Loading and Saving Test Cog."""

    def __init__(self, bot):
        self.bot = bot
        self.raid_info = bot.raid_info

    def __local_check(self, ctx):
        return checks.is_owner_check(ctx) or checks.is_dev_check(ctx)

    @commands.group(invoke_without_command=True)
    async def raiddata(self, ctx, level=None):
        """Show all raid Pokemon, showing only the raid level if provided."""
        data = []
        title = None
        if level:
            title = f"Pokemon Data for Raid {level}"
            try:
                for pkmn in self.raid_info['raid_eggs'][level]["pokemon"]:
                    pkmn = Pokemon.get_pokemon(self.bot, pkmn)
                    data.append(f"#{pkmn.id} - {pkmn.name}")
            except KeyError:
                return await ctx.send('Invalid raid level specified.')
            except:
                return await ctx.send('Error processing command')
        else:
            title = f"Pokemon Data for All Raids"
            data = []
            for pkmnlvl, vals in self.raid_info['raid_eggs'].items():
                if not vals["pokemon"]:
                    continue
                leveldata = []
                try:
                    for pkmn in vals["pokemon"]:
                        pkmn = Pokemon.get_pokemon(self.bot, pkmn)
                        leveldata.append(f"#{pkmn.id} - {pkmn.name}")
                except:
                    return await ctx.send('Error processing command')
                leveldata = '\n'.join(leveldata)
                data.append(f"**Raid {pkmnlvl} Pokemon**\n{leveldata}\n")
        data_str = '\n'.join(data)
        await ctx.send(f"**{title}**\n{data_str}")

    def in_list(self, pkmn):
        for pkmnlvl, vals in self.raid_info['raid_eggs'].items():
            if pkmn.name in vals["pokemon"]:
                return pkmnlvl
        return None

    @raiddata.command(name='remove', aliases=['rm', 'del', 'delete'])
    async def remove_rd(self, ctx, *, raid_pokemon=None):
        """Removes all pokemon provided as comma-separated arguments from the raid data.

        Example: !raiddata remove Mr Mime, Jynx, Alolan Raichu
        """
        results = []
        # remove level if erroneously provided
        raid_pokemon = re.sub(r'^\d+\s+', '', raid_pokemon)
        raid_pokemon = re.split(r'\s*,\s*', raid_pokemon)
        for pokemon in raid_pokemon:
            pkmn = Pokemon.get_pokemon(self.bot, pokemon)
            if not pkmn:
                return await ctx.send('Invalid Pokemon Name')
            hit_key = []
            name = pkmn.name.lower()
            for k, v in self.raid_info['raid_eggs'].items():
                if name in v['pokemon']:
                    hit_key.append(k)
                    self.raid_info['raid_eggs'][k]['pokemon'].remove(name)
            if hit_key:
                hits = '\n'.join(hit_key)
                result_text = f"#{pkmn.id} {pkmn.name} from {hits}"
            else:
                result_text = f"#{pkmn.id} {pkmn.name} not found in raid data"
            results.append(result_text)
        results_st = '\n'.join(results)
        await ctx.send(f"**Pokemon removed from raid data**\n{results_st}")

    def add_raid_pkmn(self, level, raid_pokemon):
        """Add raid pokemon to relevant level."""
        added = []
        failed = []
        raid_pokemon = re.split(r'\s*,\s*', raid_pokemon)
        raid_list = self.raid_info['raid_eggs'][level]['pokemon']
        for pokemon in raid_pokemon:
            pkmn = Pokemon.get_pokemon(self.bot, pokemon)
            if not pkmn:
                failed.append(pokemon)
                continue
            in_level = self.in_list(pkmn)
            name = pkmn.name.lower()
            if in_level:
                if in_level == level:
                    continue
                self.raid_info['raid_eggs'][in_level]['pokemon'].remove(name)
            raid_list.append(name)
            added.append(f"#{pkmn.id} {pkmn.name}")
        return (added, failed)

    @raiddata.command(name='add')
    async def add_rd(self, ctx, level, *, raid_pokemon=None):
        """Adds all pokemon provided as arguments to the specified raid
        level in the raid data.

        Example: !raiddata add 3 Mr Mime, Jynx, Alolan Raichu
        """

        if level not in self.raid_info['raid_eggs'].keys():
            return await ctx.send("Invalid raid level specified.")

        added, failed = self.add_raid_pkmn(level, raid_pokemon)

        result = []

        if added:
            result.append(
                f"**{len(added)} Pokemon added to Level {level} Raids:**\n"
                f"{', '.join(added)}")

        if failed:
            result.append(
                f"**{len(failed)} entries failed to be added:**\n"
                f"{', '.join(failed)}")

        await ctx.send('\n'.join(result))

    @raiddata.command(name='replace', aliases=['rp'])
    async def replace_rd(self, ctx, level, *, raid_pokemon=None):
        """All pokemon provided will replace the specified raid level
        in the raid data.

        Example: !raiddata replace 3 Mr Mime, Jynx, Alolan Raichu
        """
        if level not in self.raid_info['raid_eggs'].keys():
            return await ctx.send("Invalid raid level specified.")
        if not raid_pokemon:
            return await ctx.send("No pokemon provided.")
        old_data = tuple(self.raid_info['raid_eggs'][level]['pokemon'])
        self.raid_info['raid_eggs'][level]['pokemon'] = []
        added, failed = self.add_raid_pkmn(level, raid_pokemon)
        if not added:
            self.raid_info['raid_eggs'][level]['pokemon'].extend(old_data)

        result = []

        if added:
            result.append(
                f"**{len(added)} Pokemon added to Level {level} Raids:**\n"
                f"{', '.join(added)}")

        if failed:
            result.append(
                f"**{len(failed)} entries failed to be added:**\n"
                f"{', '.join(failed)}")

        await ctx.send('\n'.join(result))

    @raiddata.command(name='save', aliases=['commit'])
    async def save_rd(self, ctx):
        """Saves the current raid data state to the json file."""
        for pkmn_lvl in self.raid_info['raid_eggs']:
            data = self.raid_info['raid_eggs'][pkmn_lvl]["pokemon"]
            pkmn_names = [Pokemon.get_pokemon(self.bot, p).name.lower() for p in data]
            self.raid_info['raid_eggs'][pkmn_lvl]["pokemon"] = pkmn_names

        with open(ctx.bot.raid_json_path, 'w') as fd:
            json.dump(self.raid_info, fd, indent=4)
        await ctx.message.add_reaction('\u2705')

def setup(bot):
    bot.add_cog(RaidDataHandler(bot))
