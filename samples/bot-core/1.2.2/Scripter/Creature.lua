dofile("class.lua")
Creature = class()
function Creature:__init(root)
    if isString(root) then
		self._id = getCreatureIdByName(root)
		self._name = root
	elseif isNumber(root) then
		self._id = root
		self._name = getCreatureNameById(root)
	else
		error('Creature class initialized without an id or name as a parameter.')
	end
end
---------------------------------------------------
------------  Basic Properties	-------------------
---------------------------------------------------
function Creature.Name()
	return self._name
end
function Creature.LookDirection()
	return getCreatureLookDirection(self._id)
end
function Creature.Outfit()
	return getCreatureOutfit(self._id)
end
function Creature.HealthPercent()
	return getCreatureHealthPercent(self._id)
end
---------------------------------------------------
------------  Skull Properties   ------------------
---------------------------------------------------
function Creature.Skull()
	return getCreatureSkull(self._id)
end
function Creature.isWhiteSkull()
	return self.Skull() == SKULL_WHITE
end
function Creature.isRedSkull()
	return self.Skull() == SKULL_RED
end
function Creature.isOrangeSkull()
	return self.Skull() == SKULL_ORANGE
end
function Creature.isYellowSkull()
	return self.Skull() == SKULL_YELLOW
end
function Creature.isBlackSkull()
	return self.Skull() == SKULL_BLACK
end
---------------------------------------------------
------------  Shield Properties   ------------------
---------------------------------------------------
function Creature.PartyStatus()
	return getCreaturePartyStatus(self._id)
end
function Creature.isPartyLeader()
	return (self.PartyStatus() == PARTY_YELLOW or
			self.PartyStatus() == PARTY_YELLOW_SHAREDEXP or
			self.PartyStatus() == PARTY_YELLOW_NOSHAREDEXP_BLINK or
			self.PartyStatus() == PARTY_YELLOW_NOSHAREDEXP)
end
function Creature.isPartyMember()
	return (Creature.isPartyLeader() or
			self.PartyStatus() == PARTY_BLUE or
			self.PartyStatus() == PARTY_BLUE_SHAREDEXP or
			self.PartyStatus() == PARTY_BLUE_NOSHAREDEXP_BLINK or
			self.PartyStatus() == PARTY_BLUE_NOSHAREDEXP)
end
function Creature.isInvitedToParty()
	 return self.PartyStatus() == PARTY_WHITEBLUE
end
function Creature.isInvitingToParty()
	 return self.PartyStatus() == PARTY_WHITEYELLOW
end
function Creature.isSharingExp()
	return (self.PartyStatus() == PARTY_BLUE_SHAREDEXP or
			self.PartyStatus() == PARTY_YELLOW_SHAREDEXP)
end
---------------------------------------------------
------------    War Properties   ------------------
---------------------------------------------------
function Creature.WarIcon()
	return getCreatureWarIcon(self._id)
end
function Creature.isWarEnemy()
	return self.WarIcon() == WAR_ENEMY
end
function Creature.isWarAlly()
	return self.WarIcon() == WAR_ALLY
end
function Creature.isInWar()
	return (self.WarIcon() == WAR_INWAR or self.isWarAlly() or self.isWarEnemy())
end






