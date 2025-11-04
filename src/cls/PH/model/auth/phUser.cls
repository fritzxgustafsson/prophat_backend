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
    set responseObject = {}
    set responseObject."access_token" = ..generateJwt()
    set responseObject."expires_in" = 900

    return responseObject
}

Method generateJwt() As %String [ Private ]
{
    set authModule = ##class(%SYS.Python).Import("ph.utils.auth")
    return authModule."generate_jwt"(..email)
}

}
