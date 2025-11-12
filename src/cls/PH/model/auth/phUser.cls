Class PH.model.auth.phUser Extends %RegisteredObject
{

Property identifier As %String [ Private ];

Property email As %String [ Private ];

Property passwordHash As %String [ Private ];

Property accessRole As %String(VALUELIST = ",admin,member") [ Private ];

ClassMethod getDbObjectForIdentifier(identifier As %String) As PH.db.auth.phUser [ Private ]
{
    return ##class(PH.db.auth.phUser).%OpenId(identifier)
}

ClassMethod createNew() As PH.model.auth.phUser
{
    set user = ..%New()
    return user
}

ClassMethod createForRefreshToken(refreshToken As %String) As PH.model.auth.phUser
{
    set identifier = ##class(PH.db.auth.refreshToken).getUserIdentifierForToken(refreshToken)
    if (identifier = "") {
        return ""
    }

    return ..createForIdentifier(identifier)
}

ClassMethod createForEmail(email As %String) As PH.model.auth.phUser
{
    set identifier = ##class(PH.db.auth.phUser).getIdentifierForEmail(email)
    if (identifier = "") {
        return ""
    }

    return ..createForIdentifier(identifier)
}

ClassMethod createForIdentifier(identifier As %String) As PH.model.auth.phUser
{
    set dbObject = ..getDbObjectForIdentifier(identifier)
    if ('$IsObject(dbObject)) {
        return ""
    }

    set user = ..createNew()
    set user.identifier = identifier
    do user.loadFromDb(dbObject)

    return user
}

Method loadFromDb(dbUser As PH.db.auth.phUser) [ Private ]
{
    set ..email = dbUser.email
    set ..passwordHash = dbUser.passwordHash
    set ..accessRole = dbUser.accessRole
}

Method isPasswordCorrect(password As %String) As %Boolean
{
    if (..passwordHash = "") {
        return 0
    }

    set authModule = ##class(%SYS.Python).Import("ph.utils.auth")
    return authModule."is_password_correct"(password, ..passwordHash)
}

Method getLoginResponseObject() As %DynamicObject
{
    set authModule = ##class(%SYS.Python).Import("ph.utils.auth")

    set responseObject = {}
    set responseObject."access_token" = authModule."generate_jwt"(..email)

    return responseObject
}

Method generateRefreshToken() As %String
{
    set refreshToken = $System.Encryption.Base64Encode($System.Util.CreateGUID())
    set userIdentifier = ..identifier
    set expiryTimestamp = $System.SQL.DATEADD("dd", 7, ##class(%UTC).NowUTC())
    &SQL(
        INSERT INTO PH_db_auth.refreshToken 
        SET phUser = :userIdentifier, token = :refreshToken, expiresAt = :expiryTimestamp
    )
    return refreshToken
}

}
