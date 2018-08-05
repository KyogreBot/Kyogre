import os
import json

from discord.ext import commands

from meowth import utils
from meowth import checks

class GymMatching:
    def __init__(self, bot):
        self.bot = bot
        self.gym_data = self.init_json()

    def init_json(self):
        with open(os.path.join('data', 'gym_data.json')) as fd:
            return json.load(fd)

    def get_gyms(self, guild_id):
        return self.gym_data.get(str(guild_id))

    def gym_match(self, gym_name, gyms, threshold=75, isPartial=True, limit=None):
        return utils.get_match(list(gyms.keys()), gym_name, threshold, isPartial, limit)

    @commands.command(hidden=True)
    @checks.is_dev_or_owner()
    async def gym_match_test(self, ctx, gym_name):
        gyms = self.get_gyms(ctx.guild.id)
        if not gyms:
            await ctx.send('Gym matching has not been set up for this server.')
            return        
        result = self.gym_match(gym_name, gyms)
        await ctx.send(json.dumps(result))
    
    def _get_gym_info_output(self, result, gyms):
        match, score = result
        gym_info = gyms[match]
        coords = gym_info['coordinates']
        notes = gym_info.get('notes', 'No notes for this gym.')
        gym_info_str = (f"**Coordinates:** {coords}\n"
                        f"**Notes:** {notes}")
        return (f"Successful match with `{match}` "
                f"with a score of `{score}`\n{gym_info_str}")
        

def setup(bot):
    bot.add_cog(GymMatching(bot))
