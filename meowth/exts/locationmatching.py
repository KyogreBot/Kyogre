import os
import json

from discord.ext import commands

from meowth import utils
from meowth import checks

class Location:
    def __init__(self, name, latitude, longitude, regions):
        self.name = name
        self.latitude = latitude
        self.longitude = longitude
        self.regions = regions
    
    @property
    def coordinates(self):
        if self.latitude and self.longitude:
            return f"{self.latitude},{self.longitude}"
        return None
    
    @property
    def maps_url(self):
        if self.coordinates:
            query = self.coordinates
        else:
            query = self.name
            if self.regions:
                query += f"+{'+'.join(self.regions)}"
        return f"https://www.google.com/maps/search/?api=1&query={query}"

class Gym(Location):
    __name__ = "Gym"
    def __init__(self, name, latitude, longitude, region, ex_eligible):
        super().__init__(name, latitude, longitude, region)
        self.ex_eligible = ex_eligible

class Pokestop(Location):
    __name__ = "Pokestop"
    def __init__(self, name, latitude, longitude, region):
        super().__init__(name, latitude, longitude, region)

class LocationMatching:
    def __init__(self, bot):
        self.bot = bot
        self.gym_data = None
        self.stop_data = None
        self.__load_data()

    def get_all(self, guild_id):
        return self.get_gyms(guild_id).copy() + self.get_stops(guild_id).copy()
    
    def get_gyms(self, guild_id):
        return self.__process("gym", self.gym_data.get(str(guild_id), None))

    def get_stops(self, guild_id):
        return self.__process("stop", self.stop_data.get(str(guild_id), None))

    def location_match(self, name, locations, threshold=75, isPartial=True, limit=None):
        match = utils.get_match([l.name for l in locations], name, threshold, isPartial, limit)
        return [(l, score) for l in locations for match_name, score in match if l.name == match_name]
    
    @commands.command(hidden=True)
    @checks.is_dev_or_owner()
    async def location_match_test(self, ctx, type, name):
        add_prefix = False
        if not name or not type:
            return await ctx.send('Type and name are required')
        if type.startswith('stop'):
            locations = self.get_stops(ctx.guild.id)
        elif type.startswith('gym'):
            locations = self.get_gyms(ctx.guild.id)
        else:
            add_prefix = True
            locations = self.get_all(ctx.guild.id)
        if not locations:
            await ctx.send('Location matching has not been set up for this server.')
            return        
        result = self.location_match(name, locations)
        result = '\n'.join([f"{f'[{l.__name__}] ' if add_prefix else ''}{l.name} {score} ({l.latitude}, {l.longitude})" for l, score in result])
        await ctx.send(result)
    
    def _get_location_info_output(self, result, locations):
        match, score = result
        location_info = locations[match]
        coords = location_info['coordinates']
        notes = location_info.get('notes', 'No notes for this location.')
        location_info_str = (f"**Coordinates:** {coords}\n"
                        f"**Notes:** {notes}")
        return (f"Successful match with `{match}` "
                f"with a score of `{score}`\n{location_info_str}")

    def __load_data(self):
        with open(os.path.join('data', 'gym_data.json')) as fd:
            self.gym_data = json.load(fd)
        with open(os.path.join('data', 'pokestop_data.json')) as fd:
            self.stop_data = json.load(fd)

    def __process(self, type, locations):
        result = []
        for name, data in locations.items():
            coords = data['coordinates'].split(',')
            if type == "gym":
                result.append(Gym(name, coords[0], coords[1], None, data['ex_eligible']))
            elif type == "stop":
                result.append(Pokestop(name, coords[0], coords[1], None))
        return result


def setup(bot):
    bot.add_cog(LocationMatching(bot))