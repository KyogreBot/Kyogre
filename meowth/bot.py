from discord.ext import commands
from meowth.context import Context

class MeowthBot(commands.AutoShardedBot):
    """Custom Discord Bot class for Kyogre"""

    async def process_commands(self, message):
        """Processes commands that are registed with the bot and it's groups.

        Without this being run in the main `on_message` event, commands will
        not be processed.
        """
        if message.author.bot:
            return
        if message.content.startswith('!'):
            message.content = message.content.lower()
            if message.content[1] == " ":
                message.content = message.content[0] + message.content[2:]
        ctx = await self.get_context(message, cls=Context)
        if not ctx.command:
            return
        await self.invoke(ctx)
