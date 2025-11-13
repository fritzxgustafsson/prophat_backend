Class PH.devOps.sourceControl Extends %Studio.SourceControl.Base
{

Method OnAfterSave(InternalName As %String, Object As %RegisteredObject = {$$$NULLOREF}) As %Status
{
    do $System.OBJ.ExportUDL(InternalName, ..getPathAndFilenameForInternalName(InternalName))
    return $$$OK
}

Method OnAfterDelete(InternalName As %String) As %Status
{
    set pathAndFilename = ..getPathAndFilenameForInternalName(InternalName)
    if ##class(%File).Exists(pathAndFilename) {
        do ##class(%File).Delete(pathAndFilename)
    }
    
	return $$$OK
}

Method getPathAndFilenameForInternalName(InternalName As %String) As %String [ Private ]
{
    #define srcPath "/opt/iris/cls/"

    set className = $Piece(InternalName, ".CLS", 1)
    set filename = $Replace(className, ".", "/")_".cls"
    return $$$srcPath_"/"_filename
}

}
