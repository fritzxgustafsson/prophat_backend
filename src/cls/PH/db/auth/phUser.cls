Class PH.db.auth.phUser Extends %Persistent
{

Property createdAt As %TimeStamp;

Property email As %String(MAXLEN = 250);

Property passwordHash As %String(MAXLEN = 250);

Property accessRole As %String(VALUELIST = ",admin,member");

Property firstname As %String;

Property lastname As %String;

Index emailIndex On email [ Unique ];

ClassMethod getIdentifierForEmail(email As %String) As %String
{
    set identifier = ""
    &SQL(
        SELECT ID INTO :identifier
        FROM PH_db_auth.phUser
        WHERE email = :email
    )
    return identifier
}

ClassMethod createDefaultUser()
{
    set user = ..%New()

    set user.createdAt = ##class(%UTC).NowUTC()
    set user.email = "admin@prophat.com"
    set user.passwordHash = ..getHasehedPassword("test")
    set user.accessRole = "admin"

    w user.%Save()
}

ClassMethod getHasehedPassword(password As %String) As %String [ Language = python ]
{
    import ph.utils.auth
    return ph.utils.auth.hash_password(password)
}

Storage Default
{
<Data name="phUserDefaultData">
<Value name="1">
<Value>%%CLASSNAME</Value>
</Value>
<Value name="2">
<Value>createdAt</Value>
</Value>
<Value name="3">
<Value>email</Value>
</Value>
<Value name="4">
<Value>passwordHash</Value>
</Value>
<Value name="5">
<Value>accessRole</Value>
</Value>
<Value name="6">
<Value>firstname</Value>
</Value>
<Value name="7">
<Value>lastname</Value>
</Value>
</Data>
<DataLocation>^PH.db.auth.phUserD</DataLocation>
<DefaultData>phUserDefaultData</DefaultData>
<IdLocation>^PH.db.auth.phUserD</IdLocation>
<IndexLocation>^PH.db.auth.phUserI</IndexLocation>
<StreamLocation>^PH.db.auth.phUserS</StreamLocation>
<Type>%Storage.Persistent</Type>
}

}
