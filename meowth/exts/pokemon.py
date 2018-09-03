from discord.ext import commands
import discord
from string import ascii_lowercase

from meowth import utils
from meowth.exts.db.kyogredb import PokemonTable

from discord.ext.commands import CommandError

class PokemonNotFound(CommandError):
    """Exception raised when Pokemon given does not exist."""
    def __init__(self, pokemon, retry=True):
        self.pokemon = pokemon
        self.retry = retry

class Pokedex:
    def __init__(self, bot):
        self.bot = bot

class Pokemon():
    """Represents a Pokemon.

    This class contains the attributes of a specific pokemon, and
    provides methods of which to get specific info and results on it.

    Parameters
    -----------
    bot: :class:`eevee.core.bot.Eevee`
        Current instance of Eevee
    pkmn: str or int
        The name or id of a Pokemon
    guild: :class:`discord.Guild`, optional
        The guild that is requesting the Pokemon
    moveset: :class:`list` or :class:`tuple` of :class:`str`, optional
        `kwarg-only:` The two moves of this Pokemon
    weather: :class:`str`, optional
        `kwarg-only:` Weather during the encounter

    Raises
    -------
    :exc:`.errors.PokemonNotFound`
        The pkmn argument was not a valid index and was not found in the
        list of Pokemon names.

    Attributes
    -----------
    species: :class:`str`
        Lowercase string representing the species of the Pokemon (formless)
    id: :class:`int`
        Pokemon ID number
    types: :class:`list` of :class:`str`
        A :class:`list` of the Pokemon's types
    moveset: :class:`list` or :class:`tuple` of :class:`str`
        The two moves of this Pokemon
    weather: :class:`str`
        Weather during the encounter
    guild: :class:`discord.Guild`
        Guild that created the Pokemon
    bot: :class:`eevee.core.bot.Eevee`
        Current instance of Eevee
    """

    __slots__ = ('species', 'id', 'types', 'bot', 'guild', 'pkmn_list',
                 'pb_raid', 'weather', 'moveset', 'form', 'shiny', 'alolan', 'legendary', 'mythical')
    
    _form_list = [
        'normal', 'sunny', 'rainy', 'snowy', 'sunglasses',
        'ash', 'party', 'witch', 'santa', 'summer',
        'defense', 'attack', 'speed'
    ]
    _stat_forms = [
        'sunny', 'rainy', 'snowy', 'defense', 'attack', 'speed'
    ]
    _prefix_forms = _form_list
    _form_dict = {
        'squirtle': ['sunglasses'],
        'wartortle': ['sunglasses'],
        'blastoise': ['sunglasses'],
        'pikachu':  ['ash', 'party', 'witch', 'santa', 'summer'],
        'raichu':  ['ash', 'party', 'witch', 'santa', 'summer'],
        'pichu':  ['ash', 'party', 'witch', 'santa', 'summer'],
        'unown': list(ascii_lowercase + '!?'),
        'spinda': [str(n) for n in range(1, 9)],
        'castform': ['normal', 'rainy', 'snowy', 'sunny'],
        'deoxys': ['defense', 'normal', 'attack', 'speed']			
    }
    _pkmn_dict = {r['name'].lower(): r for r in PokemonTable.select().where(PokemonTable.released == True).dicts()}

    def __init__(self, bot, pkmn, guild=None, **attribs):
        self.bot = bot
        self.guild = guild
        p_obj = Pokemon.find_obj(pkmn)
        if not p_obj:
            raise PokemonNotFound(pkmn)
        self.id = p_obj['id']
        self.species = p_obj['name']
        self.pb_raid = None
        self.weather = attribs.get('weather', None)
        self.moveset = attribs.get('moveset', [])
        self.form = attribs.get('form', '')
        if self.form not in Pokemon._form_dict.get(self.species, []):
            self.form = None
        self.shiny = attribs.get('shiny', False) and p_obj['shiny']
        self.alolan = attribs.get('alolan', False) and p_obj['alolan']
        self.legendary = p_obj['legendary']
        self.mythical = p_obj['mythical']
        if self.alolan:
            self.types = p_obj['types']['alolan']
        else:
            self.types = p_obj['types']['default']

    def __str__(self):
        return self.name

    @property
    def name(self):
        # name without cosmetic modifiers (for identifying substantive differences)
        name = self.species.title()
        if self.form and self.form in Pokemon._stat_forms:
            if self.form in Pokemon._prefix_forms:
                name = self.form.title() + name
            else:
                name = name + self.form.title()
        if self.alolan:
            name = f'Alolan {name}' 
        return name
    
    @property
    def full_name(self):
        # name with all modifiers
        name = self.species.title()
        if self.form:
            if self.form in Pokemon._prefix_forms:
                name = self.form.title() + name
            else:
                name = name + self.form.title()
        if self.alolan:
            name = f'Alolan {name}' 
        if self.shiny:
            name = f'Shiny {name}'
        return name

    async def get_pb_raid(self, weather=None, userid=None, moveset=None):
        """Get a PokeBattler Raid for this Pokemon

        This can quickly produce a PokeBattler Raid for the current
        Pokemon, with the option of providing a PokeBattler User ID to
        get customised results.

        The resulting PokeBattler Raid object will be saved under the
        `pb_raid` attribute of the Pokemon instance for later retrieval,
        unless it's customised with an ID.

        Parameters
        -----------
        weather: :class:`str`, optional
            The weather during the raid
        userid: :class:`int`, optional
            The Pokebattler User ID to generate the PB Raid with
        moveset: list or tuple, optional
            A :class:`list` or :class:`tuple` with a :class:`str` representing
            ``move1`` and ``move2`` of the Pokemon.

        Returns
        --------
        :class:`eevee.cogs.pokebattler.objects.PBRaid` or :obj:`None`
            PokeBattler Raid instance or None if not a Raid Pokemon.

        Example
        --------

        .. code-block:: python3

            pokemon = Pokemon(ctx.bot, 'Groudon')
            moveset = ('Dragon Tail', 'Solar Beam')
            pb_raid = pokemon.get_pb_raid('windy', 12345, moveset)
        """

        # if a Pokebattler Raid exists with the same settings, return it
        if self.pb_raid:
            if not (weather or userid) and not moveset:
                return self.pb_raid
            if weather:
                self.pb_raid.change_weather(weather)

        # if it doesn't exist or settings changed, generate it
        else:
            pb_cog = self.bot.cogs.get('PokeBattler', None)
            if not pb_cog:
                return None
            if not weather:
                weather = self.weather or 'DEFAULT'
            weather = pb_cog.PBRaid.get_weather(weather)
            pb_raid = await pb_cog.PBRaid.get(
                self.bot, self, weather=self.weather, userid=userid)

        # set the moveset for the Pokebattler Raid
        if not moveset:
            moveset = self.moveset
        try:
            pb_raid.set_moveset(moveset)
        except RuntimeError:
            pass

        # don't save it if it's a user-specific Pokebattler Raid
        if not userid:
            self.pb_raid = pb_raid

        return pb_raid

    @property
    def img_url(self):
        """:class:`str` : Pokemon sprite image URL"""
        pkmn_no = str(self.id).zfill(3)
        if self.form:
            if self.form == '?':
                form_str = 'question'
            else:    
                form_str = self.form
        else:
            form_str = ""
        if self.alolan:
            alolan_str = "a"
        else:
            alolan_str = ""
        if self.shiny:
            shiny_str = "s"
        else:
            shiny_str = ""
        return ('https://raw.githubusercontent.com/klords/Kyogre/master/'
                f'images/pkmn/{pkmn_no}{form_str}_{alolan_str}{shiny_str}.png?cache=3')

    # async def colour(self):
    #     """:class:`discord.Colour` : Discord colour based on Pokemon sprite."""
    #     return await url_color(self.img_url)

    @property
    def is_raid(self):
        """:class:`bool` : Indicates if the pokemon can show in Raids"""
        return self.name.lower() in utils.get_raidlist(self.bot)

    @property
    def is_exraid(self):
        """:class:`bool` : Indicates if the pokemon can show in Raids"""
        return self.name.lower() in self.bot.raid_info['raid_eggs']['EX']['pokemon']

    @property
    def raid_level(self):
        """:class:`int` or :obj:`None` : Returns raid egg level"""
        return utils.get_level(self.bot, self.name)

    # def max_raid_cp(self, weather_boost=False):
    #     """:class:`int` or :obj:`None` : Returns max CP on capture after raid
    #     """
    #     key = "max_cp_w" if weather_boost else "max_cp"
    #     return self.bot.raid_pokemon[self.name][key] if self.is_raid else None

    def role(self, guild=None):
        """:class:`discord.Role` or :obj:`None` : Returns the role for
        this Pokemon
        """
        if not guild:
            guild = self.guild
        if not guild:
            return None
        return discord.utils.get(guild.roles, name=self.name)

    def set_guild(self, guild):
        """:class:`discord.Guild` or :obj:`None` : Sets the relevant Guild"""
        self.guild = guild

    @property
    def weak_against(self):
        """:class:`dict` : Returns a dict of all types the Pokemon is
        weak against.
        """
        types_eff = {}
        for t, v in self.type_effects.items():
            if round(v, 3) >= 1:
                types_eff[t] = v
        return types_eff

    @property
    def strong_against(self):
        """:class:`dict` : Returns a dict of all types the Pokemon is
        strong against.
        """
        types_eff = {}
        for t, v in self.type_effects.items():
            if round(v, 3) <= -1:
                types_eff[t] = v
        return types_eff

    @property
    def type_effects(self):
        """:class:`dict` : Returns a dict of all Pokemon types and their
        relative effectiveness as values.
        """
        type_eff = {}
        for _type in self.types:
            for atk_type in self.bot.defense_chart[_type]:
                if atk_type not in type_eff:
                    type_eff[atk_type] = 1
                type_eff[atk_type] *= utils.get_effectiveness(self.bot.defense_chart[_type][atk_type])
        return type_eff

    @property
    def type_effects_grouped(self):
        """:class:`dict` : Returns a dict of all Pokemon types and their
        relative effectiveness as values, grouped by the following:
            * ultra
            * super
            * low
            * worst
        """
        type_eff_dict = {
            'ultra' : [],
            'super' : [],
            'low'   : [],
            'worst' : []
        }
        for t, v in self.type_effects.items():
            if v > 1.9:
                type_eff_dict['ultra'].append(t)
            elif v > 1.3:
                type_eff_dict['super'].append(t)
            elif v < 0.6:
                type_eff_dict['worst'].append(t)
            else:
                type_eff_dict['low'].append(t)
        return type_eff_dict

    @classmethod
    async def convert(cls, ctx, argument):
        """Returns a pokemon that matches the value
        of the argument that's being converted.

        It first will check if it's a valid ID, and if not, will perform
        a fuzzymatch against the list of Pokemon names.

        Returns
        --------
        :class:`Pokemon` or :class:`dict`
            If there was a close or exact match, it will return a valid
            :class:`Pokemon`.
            If the match is lower than 80% likeness, it will return a
            :class:`dict` with the following keys:
                * ``suggested`` - Next best guess based on likeness.
                * ``original`` - Original value of argument provided.

        Raises
        -------
        :exc:`discord.ext.commands.BadArgument`
            The argument didn't match a Pokemon ID or name.
        """
        argument = argument.lower()
        if 'shiny' in argument.lower():
            shiny = True
            argument = argument.replace('shiny','').strip()
        else:
            shiny = False
        if 'alolan' in argument.lower():
            alolan = True
            argument = argument.replace('alolan', '').strip()
        else:
            alolan = False
        form_list = Pokemon._form_list
        f = next((x for x in form_list if x in argument.lower()), None)
        if f:
            form = f.strip()
            argument = argument.replace(f, '').strip()
        else:
            form = None
        
        p_obj = Pokemon.find_obj(argument)
        if not p_obj:
            pkmn_list = [p for p in Pokemon._pkmn_dict]
            match, score = utils.get_match(pkmn_list, argument)
        else:
            match = p_obj['name']
            score = 100

        if match:
            if score >= 80:
                result = cls(ctx.bot, match, ctx.guild, shiny=shiny, alolan=alolan, form=form)
            else:
                result = {
                    'suggested' : match,
                    'original'   : argument
                }

        if not result:
            raise commands.errors.BadArgument(
                'Pokemon "{}" not valid'.format(argument))
        return result
    
    @classmethod
    def find_obj(cls, pkmn):
        if pkmn.isdigit():
            p_obj = next((v for k, v in Pokemon._pkmn_dict.items() if v['id'] == int(pkmn)), None)
        else:
            p_obj = next((v for k, v in Pokemon._pkmn_dict.items() if k == pkmn.strip().lower()), None)
        return p_obj

    @classmethod
    def get_pokemon(cls, bot, argument, guild=None):
        argument = argument.lower()
        if 'shiny' in argument:
            shiny = True
            argument = argument.replace('shiny', '').strip()
        else:
            shiny = False
        if 'alolan' in argument:
            alolan = True
            argument = argument.replace('alolan', '').strip()
        else:
            alolan = False

        form = None
        detected_forms = []
        form_check = None
        candidates = [f for f in Pokemon._form_list if f in argument]
        for c in candidates:
            detected_forms.append(c)
            argument = argument.replace(c, '').strip()

        arg_split = argument.split()
        if len(arg_split) > 1:
            argument = arg_split[0]
            form_check = arg_split[1]

        p_obj = Pokemon.find_obj(argument)
        if not p_obj:
            pkmn_list = [p for p in Pokemon._pkmn_dict]
            match = utils.get_match(pkmn_list, argument, score_cutoff=80)[0]
        else:
            match = p_obj['name']

        if not match:
            return None

        form_list = Pokemon._form_dict.get(match, [])
        if form_check and form_check in form_list:
            detected_forms.append(form_check)
        forms = [d for d in detected_forms if d in form_list]
        if forms:
            form = ' '.join(forms)

        return cls(bot, str(match), guild, shiny=shiny, alolan=alolan, form=form)


def setup(bot):
    bot.add_cog(Pokedex(bot))
