Class PH.Service Extends %CSP.REST
{

Parameter CONTENTTYPE = "application/json";

Parameter SECURITYRESOURCE;

XData UrlMap
{
<Routes>
    <Route Url="/iris" Method="GET" Call="getIrisResponse"/>
    <Route Url="/python" Method="GET" Call="getPythonResponse"/>
    <Route Url="/pythonlib" Method="GET" Call="getPythonLibResponse"/>
    <Route Url="/pythoniris" Method="GET" Call="getPythonIrisResponse"/>
    <Route Url="/all" Method="GET" Call="getAllResponse"/>
</Routes>
}

ClassMethod getIrisResponse() As %Status
{
    write { "iris": "simple string" }.%ToJSON()
    Quit $$$OK
}

ClassMethod getPythonResponse() As %Status
{
    write { "python": (..getPythonVal()) }.%ToJSON()
    Quit $$$OK
}

ClassMethod getPythonVal() [ Language = python ]
{
    import ph.test
    return ph.test.get_string()
}

ClassMethod getPythonLibResponse() As %Status
{
    write { "pythonLib": (..getPythonLibVal()) }.%ToJSON()
    Quit $$$OK
}

ClassMethod getPythonLibVal() [ Language = python ]
{
    import ph.test
    return ph.test.get_joke()
}

ClassMethod getPythonIrisResponse() As %Status
{
    write { "pythonIrisVal": (..getPythonIrisVal()) }.%ToJSON()
    Quit $$$OK
}

ClassMethod getPythonIrisVal() [ Language = python ]
{
    import ph.test
    return ph.test.get_iris_val()
}

ClassMethod getAllResponse() As %Status
{
    write {
        "iris": "simple string",
        "python": (..getPythonVal()),
        "pythonLib": (..getPythonLibVal()),
        "pythonIrisVal": (..getPythonIrisVal())
    }.%ToJSON()
    Quit $$$OK
}

}
