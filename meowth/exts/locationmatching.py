import os
import json

from discord.ext import commands

from meowth import utils, checks
from meowth.exts.db.kyogredb import *

class Location:
    def __init__(self, name, latitude, longitude, region):
        self.name = name
        self.latitude = latitude
        self.longitude = longitude
        self.region = region
    
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
            if self.region:
                query += f"+{'+'.join(self.region)}"
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

    def get_all(self, guild_id, regions=None):
        return self.get_gyms(guild_id, regions=regions) + self.get_stops(guild_id, regions=regions)
    
    def get_gyms(self, guild_id, regions=None):
        result = (GymTable
                    .select(LocationTable.name, 
                            LocationTable.latitude, 
                            LocationTable.longitude, 
                            RegionTable.name.alias('region'),
                            GymTable.ex_eligible)
                    .join(LocationTable)
                    .join(LocationRegionRelation)
                    .join(RegionTable)
                    .where((LocationTable.guild == guild_id) &
                           (LocationTable.guild == RegionTable.guild)))
        if regions:
            if not isinstance(regions, list):
                regions = [regions]
            result = result.where(RegionTable.name << regions)
        result = result.objects(Gym)
        return [o for o in result]

    def get_stops(self, guild_id, regions=None):
        result = (PokestopTable
                    .select(LocationTable.name, 
                            LocationTable.latitude, 
                            LocationTable.longitude, 
                            RegionTable.name.alias('region'))
                    .join(LocationTable)
                    .join(LocationRegionRelation)
                    .join(RegionTable)
                    .where((LocationTable.guild == guild_id) &
                           (LocationTable.guild == RegionTable.guild)))
        if regions:
            if not isinstance(regions, list):
                regions = [regions]
            result = result.where(RegionTable.name << regions)
        result = result.objects(Pokestop)
        return [o for o in result]

    def location_match(self, name, locations, threshold=75, isPartial=True, limit=None):
        match = utils.get_match([l.name for l in locations], name, threshold, isPartial, limit)
        if not isinstance(match, list):
            match = [match]
        return [(l, score) for l in locations for match_name, score in match if l.name == match_name]
    
    @commands.command(hidden=True, aliases=["lmt"])
    @checks.is_dev_or_owner()
    async def location_match_test(self, ctx, *, content=None):
        add_prefix = False
        if ',' not in content:
            return await ctx.send('Comma-separated type and name are required')
        loc_type, name, *regions = [c.strip() for c in content.split(',')]
        if not name or not loc_type:
            return await ctx.send('Type and name are required')
        loc_type = loc_type.lower()
        if 'stop' in loc_type:
            locations = self.get_stops(ctx.guild.id, regions)
        elif loc_type.startswith('gym'):
            locations = self.get_gyms(ctx.guild.id, regions)
        else:
            add_prefix = True
            locations = self.get_all(ctx.guild.id, regions)
        if not locations:
            await ctx.send('Location matching has not been set up for this server.')
            return        
        result = self.location_match(name, locations)
        if not result:
            result = 'No matches found!'
        else:
            result = '\n'.join([f"{f'[{l.__name__}] ' if add_prefix else ''}{l.name} {score} ({l.latitude}, {l.longitude}) {l.region}" for l, score in result])
        for i in range(len(result) // 2001 + 1):
            await ctx.send(result[2001*i:2001*(i+1)])
    
    def _get_location_info_output(self, result, locations):
        match, score = result
        location_info = locations[match]
        coords = location_info['coordinates']
        notes = location_info.get('notes', 'No notes for this location.')
        location_info_str = (f"**Coordinates:** {coords}\n"
                        f"**Notes:** {notes}")
        return (f"Successful match with `{match}` "
                f"with a score of `{score}`\n{location_info_str}")

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