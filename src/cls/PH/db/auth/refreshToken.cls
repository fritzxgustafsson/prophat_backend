Class PH.db.auth.refreshToken Extends %Persistent
{

Property phUser As PH.db.auth.phUser;

Property token As %String(MAXLEN = 250);

Property expiresAt As %TimeStamp;

Index tokenIndex On token [ Unique ];

ClassMethod getUserIdentifierForToken(token As %String) As %String
{
    set userIdentifier = ""
    &SQL(
        SELECT phUser INTO :userIdentifier
        FROM PH_db_auth.refreshToken
        WHERE token = :token
        AND expiresAt > CURRENT_TIMESTAMP
    )
    if +SQLCODE = 100 {
        return ""
    }
    return userIdentifier
}

ClassMethod deleteForToken(token As %String)
{
    &SQL(DELETE FROM PH_db_auth.refreshToken WHERE token = :token)
}

Storage Default
{
<Data name="refreshTokenDefaultData">
<Value name="1">
<Value>%%CLASSNAME</Value>
</Value>
<Value name="2">
<Value>phUser</Value>
</Value>
<Value name="3">
<Value>token</Value>
</Value>
<Value name="4">
<Value>expiresAt</Value>
</Value>
</Data>
<DataLocation>^PH.db.auth.refreshTokenD</DataLocation>
<DefaultData>refreshTokenDefaultData</DefaultData>
<IdLocation>^PH.db.auth.refreshTokenD</IdLocation>
<IndexLocation>^PH.db.auth.refreshTokenI</IndexLocation>
<StreamLocation>^PH.db.auth.refreshTokenS</StreamLocation>
<Type>%Storage.Persistent</Type>
}

}
