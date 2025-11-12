Class PH.model.auth.phUserList Extends %ListOfObjects
{

ClassMethod createForAllUsers() As PH.model.auth.phUserList
{
    set list = ..%New()

    set query = "SELECT ID As userIdentifier FROM PH_db_auth.phUser"
    set statement = ##class(%SQL.Statement).%New()
    do statement.%Prepare(query)
    set resultSet = statement.%Execute()
    while resultSet.%Next() {
        set userIdentifier = resultSet.%Get("userIdentifier")
        set user = ##class(PH.model.auth.phUser).createForIdentifier(userIdentifier)
        do list.Insert(user)
    }

    return list
}

Method getApiResponseObject() As %DynamicArray
{
    set response = []

    for i = 1 : 1 : ..Count() {
        set user = ..GetAt(i)
        do response.%Push(user.getApiResponseObject())
    }

    return response
}

Storage Custom
{
<Type>%Library.CompleteCustomStorage</Type>
}

}
