import json
from peewee import Proxy, chunked
from playhouse.apsw_ext import *
from playhouse.sqlite_ext import JSONField
from playhouse.migrate import *

class KyogreDB:
    _db = Proxy()
    _migrator = None
    @classmethod
    def start(cls, db_path):
        handle = APSWDatabase(db_path, pragmas={
            'journal_mode': 'wal',
            'cache_size': -1 * 64000,
            'foreign_keys': 1,
            'ignore_check_constraints': 0
        })
        cls._db.initialize(handle)
        # ensure db matches current schema
        cls._db.create_tables([
            LocationTable, TeamTable, GuildTable, 
            TrainerTable, PokemonTable, SilphcardTable, 
            RegionTable, LocationRegionRelation, PokestopTable, 
            GymTable, TrainerReportRelation, QuestTable, 
            ResearchTable, SightingTable, RaidBossRelation, 
            RaidTable, SubscriptionTable, TradeTable,
            LocationNoteTable, RewardTable
        ])
        cls.init()
        cls._migrator = SqliteMigrator(cls._db)

    @classmethod
    def stop(cls):
        return cls._db.close()
    
    @classmethod
    def init(cls):
        #check team
        try:
            TeamTable.get()
        except:
            TeamTable.reload_default()
        #check pokemon
        try:
            PokemonTable.get()
        except:
            PokemonTable.reload_default()
        #check regions
        try:
            RegionTable.get()
        except:
            RegionTable.reload_default()
        #check locations
        try:
            LocationTable.get()
        except:
            LocationTable.reload_default()
        #check quests
        try:
            QuestTable.get()
        except:
            QuestTable.reload_default()

class BaseModel(Model):
    class Meta:
        database = KyogreDB._db

class TeamTable(BaseModel):
    name = TextField(unique=True)
    emoji = TextField()

    @classmethod
    def reload_default(cls):
        if not KyogreDB._db:
            return
        try:
            cls.delete().execute()
        except:
            pass
        with open('config.json', 'r') as f:
            team_data = json.load(f)['team_dict']
        for name, emoji in team_data.items():
            cls.insert(name=name, emoji=emoji).execute()

class GuildTable(BaseModel):
    snowflake = BigIntegerField(unique=True)
    config_dict = JSONField(null=True)

class TrainerTable(BaseModel):
    snowflake = BigIntegerField(index=True)
    team = ForeignKeyField(TeamTable, backref='trainers', null=True)
    guild = ForeignKeyField(GuildTable, field=GuildTable.snowflake, backref='trainers')

    class Meta:
        constraints = [SQL('UNIQUE(snowflake, guild_id)')]

class PokemonTable(BaseModel):
    id = IntegerField(primary_key=True)
    name = TextField(index=True)
    legendary = BooleanField()
    mythical = BooleanField()
    shiny = BooleanField()
    alolan = BooleanField()
    types = JSONField()
    released = BooleanField(index=True)

    @classmethod
    def reload_default(cls):
        if not KyogreDB._db:
            return
        try:
            cls.delete().execute()
        except:
            pass
        with open('data/pkmn_data.json', 'r') as f:
            pkmn_data = json.load(f)
        with KyogreDB._db.atomic():
            for chunk in chunked(pkmn_data, 50):
                cls.insert_many(chunk).execute()

class SilphcardTable(BaseModel):
    trainer = BigIntegerField(index=True)
    name = TextField(index=True)
    url = TextField(unique=True)

class RegionTable(BaseModel):
    name = TextField(index=True)
    area = TextField(null=True)
    guild = ForeignKeyField(GuildTable, field=GuildTable.snowflake, backref='regions', index=True)

    @classmethod
    def reload_default(cls):
        if not KyogreDB._db:
            return
        try:
            cls.delete().execute()
        except:
            pass
        with open('data/region_data.json', 'r') as f:
            region_data = json.load(f)
        with KyogreDB._db.atomic():
            for region in region_data:
                try:
                    if 'guild' in region and region['guild']:
                        for guild_id in region['guild'].split(','):
                            guild, __ = GuildTable.get_or_create(snowflake=guild_id)
                            RegionTable.create(name=region['name'], area=None, guild=guild)
                except Exception as e:
                    import pdb; pdb.set_trace()
                    print(e)
    
    class Meta:
        constraints = [SQL('UNIQUE(name, guild_id)')]

class LocationTable(BaseModel):
    name = TextField(index=True)
    latitude = TextField()
    longitude = TextField()
    guild = ForeignKeyField(GuildTable, field=GuildTable.snowflake, backref='locations', index=True)

    @classmethod
    def create_location(ctx, name, data):
        try:
            latitude, longitude = data['coordinates'].split(',')
            if 'guild' in data and data['guild']:
                for guild_id in data['guild'].split(','):
                    with KyogreDB._db.atomic():
                        guild, __ = GuildTable.get_or_create(snowflake=guild_id)
                        location = LocationTable.create(name=name, latitude=latitude, longitude=longitude, guild=guild)
                        if 'region' in data and data['region']:
                            for region_name in data['region'].split(','):
                                with KyogreDB._db.atomic():
                                    # guild_id used here because peewee will not get correctly if obj used and throw error
                                    region, __ = RegionTable.get_or_create(name=region_name, area=None, guild=guild_id)
                                    LocationRegionRelation.create(location=location, region=region)
                        if 'notes' in data:
                            for note in data['notes']:
                                LocationNoteTable.create(location=location, note=note)
                        if 'ex_eligible' in data:
                            GymTable.create(location=location, ex_eligible=data['ex_eligible'])
                        else:
                            PokestopTable.create(location=location)
        except Exception as e:
            import pdb; pdb.set_trace()
            print(e)

    @classmethod
    def reload_default(cls):
        if not KyogreDB._db:
            return
        try:
            cls.delete().execute()
        except:
            pass
        with open('data/gym_data.json', 'r') as f:
            gym_data = json.load(f)
        with open('data/pokestop_data.json', 'r') as f:
            pokestop_data = json.load(f)
        for name, data in gym_data.items():
            LocationTable.create_location(name, data)
        for name, data in pokestop_data.items():
            LocationTable.create_location(name, data)

class LocationNoteTable(BaseModel):
    location = ForeignKeyField(LocationTable, backref='notes')
    note = TextField()

class LocationRegionRelation(BaseModel):
    location = ForeignKeyField(LocationTable, backref='regions')
    region = ForeignKeyField(RegionTable, backref='locations')

class PokestopTable(BaseModel):
    location = ForeignKeyField(LocationTable, backref='pokestops', primary_key=True)

class GymTable(BaseModel):
    location = ForeignKeyField(LocationTable, backref='gyms', primary_key=True)
    ex_eligible = BooleanField(index=True)

class TrainerReportRelation(BaseModel):
    created = DateTimeField(index=True)
    trainer = BigIntegerField(index=True)
    location = ForeignKeyField(LocationTable, backref='reports', index=True)

class QuestTable(BaseModel):
    name = TextField(unique=True)
    reward_pool = JSONField()

    @classmethod
    def reload_default(cls):
        if not KyogreDB._db:
            return
        try:
            cls.delete().execute()
        except:
            pass
        with open('data/quest_data.json', 'r') as f:
            quest_data = json.load(f)
        with KyogreDB._db.atomic():
            for quest in quest_data:
                try:
                    name = quest['name']
                    pool = quest['reward_pool']
                    QuestTable.create(name=name, reward_pool=pool)
                    parseRewardPool(pool)
                except Exception as e:
                    import pdb; pdb.set_trace()
                    print(e)

class ResearchTable(BaseModel):
    trainer_report = ForeignKeyField(TrainerReportRelation, backref='research')
    quest = ForeignKeyField(QuestTable, backref='reports', index=True)

def parseRewardPool(pool):
    for key,val in pool["items"].items():
        try:
            RewardTable.create(name=key)
        except Exception as e:
            pass

class Reward():
    def __init__(self, name, quantity):
        self.name = name
        self.quantity = quantity

class RewardTable(BaseModel):
    name = TextField(index=True, unique=True)
    quantity = IntegerField(null=True)

class SightingTable(BaseModel):
    trainer_report = ForeignKeyField(TrainerReportRelation, backref='sightings')
    pokemon = ForeignKeyField(PokemonTable, backref='sightings')

class BossTable(BaseModel):
    pokemon = TextField(index=True)
    level = TextField(index=True)

class RaidTable(BaseModel):
    trainer_report = ForeignKeyField(TrainerReportRelation, backref='raids')
    level = TextField(index=True)
    type = TextField(index=True)
    next_event_time = DateTimeField(index=True)
    channel = BigIntegerField(index=True)
    trainer_dict = JSONField()

class RaidBossRelation(BaseModel):
    boss = ForeignKeyField(BossTable, backref='raids')
    raid = ForeignKeyField(RaidTable, backref='boss')

class SubscriptionTable(BaseModel):
    trainer = BigIntegerField(index=True)
    type = TextField(index=True)
    target = TextField(index=True)

    class Meta:
        constraints = [SQL('UNIQUE(trainer, type, target)')]

class TradeTable(BaseModel):
    trainer = BigIntegerField(index=True)
    channel = BigIntegerField()
    offer = TextField()
    wants = TextField()