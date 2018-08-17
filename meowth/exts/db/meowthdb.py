import json
from peewee import Proxy, chunked
from playhouse.apsw_ext import *
from playhouse.sqlite_ext import JSONField

class MeowthDB:
    _db = Proxy()
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
            RewardTable, ResearchTable, SightingTable, 
            RaidBossRelation, RaidTable, SubscriptionTable
        ])
        cls.init()

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

class BaseModel(Model):
    class Meta:
        database = MeowthDB._db

class TeamTable(BaseModel):
    name = TextField(unique=True)
    emoji = TextField()

    @classmethod
    def reload_default(cls):
        if not MeowthDB._db:
            return
        try:
            cls.delete()
        except:
            pass
        with open('config.json', 'r') as f:
            team_data = json.loads(f.read())['team_dict']
        for name, emoji in team_data.items():
            cls.insert(name=name, emoji=emoji).execute()

class GuildTable(BaseModel):
    id = BigIntegerField(primary_key=True)

class GuildConfigTable(BaseModel):
    guild = BigIntegerField(primary_key=True)
    welcome_enabled = BooleanField()
    welcome_message = TextField()
    want_enabled = BooleanField()
    raid_enabled = BooleanField()
    raid_categories = TextField()
    exraid_enabled = BooleanField()
    exraid_categories = TextField()
    exraid_permissions = TextField()
    counters_enabled = BooleanField()
    counters_auto_levels = TextField()
    wild_enabled = BooleanField()
    research_enabled = BooleanField()
    archive_enabled = BooleanField()
    archive_category = TextField()
    invite_enabled = BooleanField()
    team_enabled = BooleanField()

class TrainerTable(BaseModel):
    discordID = BigIntegerField(index=True)
    team = ForeignKeyField(TeamTable, backref='trainers')
    guild = ForeignKeyField(GuildTable, backref='trainers', index=True)

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
        if not MeowthDB._db:
            return
        try:
            cls.delete()
        except:
            pass
        with open('data/pkmn_data.json', 'r') as f:
            pkmn_data = json.loads(f.read())
        with MeowthDB._db.atomic():
            for chunk in chunked(pkmn_data, 50):
                cls.insert_many(chunk).execute()

class SilphcardTable(BaseModel):
    trainer = ForeignKeyField(TrainerTable, backref='silphcard')
    name = TextField(index=True)
    url = TextField(unique=True)

class RegionTable(BaseModel):
    name = TextField(index=True)
    area = TextField()

class LocationTable(BaseModel):
    name = TextField(index=True)
    latitude = TextField()
    longitude = TextField()

class LocationNoteTable(BaseModel):
    location = ForeignKeyField(LocationTable, backref='notes')
    note = TextField()

class LocationRegionRelation(BaseModel):
    location = ForeignKeyField(LocationTable)
    region = ForeignKeyField(RegionTable)

class PokestopTable(BaseModel):
    location = ForeignKeyField(LocationTable, primary_key=True)

class GymTable(BaseModel):
    location = ForeignKeyField(LocationTable, primary_key=True)
    ex_eligible = BooleanField(index=True)

class TrainerReportRelation(BaseModel):
    created = DateTimeField(index=True)
    trainer = ForeignKeyField(TrainerTable, backref='reports')
    location = ForeignKeyField(LocationTable, backref='reports')

class QuestTable(BaseModel):
    name = TextField(index=True)

class RewardTable(BaseModel):
    name = TextField(index=True)

class ResearchTable(BaseModel):
    trainer_report = ForeignKeyField(TrainerReportRelation, backref='research')
    quest = ForeignKeyField(QuestTable, backref='reports', index=True)
    reward = ForeignKeyField(RewardTable, backref='reports', index=True)

class SightingTable(BaseModel):
    pokemon = ForeignKeyField(PokemonTable, backref='sightings')
    location = ForeignKeyField(LocationTable, backref='sightings')

class BossTable(BaseModel):
    pokemon = ForeignKeyField(PokemonTable)
    level = TextField(index=True)

class RaidTable(BaseModel):
    trainer_report = ForeignKeyField(TrainerReportRelation, backref='raids')
    level = TextField(index=True)
    next_event_type = TextField(index=True)
    next_event_time = DateTimeField(index=True)
    channel = BigIntegerField(index=True)

class RaidBossRelation(BaseModel):
    boss = ForeignKeyField(BossTable, backref='raids')
    raid = ForeignKeyField(RaidTable, backref='boss')

class SubscriptionTable(BaseModel):
    trainer = BigIntegerField(index=True)
    guild = BigIntegerField(index=True)
    type = TextField(index=True)
    target = TextField(index=True)

    class Meta:
        constraints = [SQL('UNIQUE(trainer, type, target)')]
