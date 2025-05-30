# Localized	05/07/2022 06:58 AM (GMT)	303:7.0.30723 	MSFT_ServiceResource.strings.psd1
# Localized resources for MSFT_UserResource

ConvertFrom-StringData @'
###PSLOC
ServiceNotFound=Service '{0}' not found.
CannotStartAndDisable=Cannot start and disable a service.
CannotStopServiceSetToStartAutomatically=Cannot stop a service and set it to start automatically.
ServiceAlreadyStarted=Service '{0}' already started, no action required.
ServiceStarted=Service '{0}' started.
ServiceStopped=Service '{0}' stopped.
ErrorStartingService=Failure starting service '{0}'. Please check the path '{1}' provided for the service. Message: '{2}'
OnlyOneParameterCanBeSpecified=Only one of the following parameters can be specified: '{0}', '{1}'.
StartServiceWhatIf=Start Service
ServiceAlreadyStopped=Service '{0}' already stopped, no action required.
ErrorStoppingService=Failure stopping service '{0}'. Message: '{1}'
ErrorRetrievingServiceInformation=Failure retrieving information for service '{0}'. Message: '{1}'
ErrorSettingServiceCredential=Failure setting credentials for service '{0}'. Message: '{1}'
SetCredentialWhatIf=Set Credential
SetStartupTypeWhatIf=Set Start Type
ErrorSettingServiceStartupType=Failure setting start type for service '{0}'. Message: '{1}'
TestUserNameMismatch=User name for service '{0}' is '{1}'. It does not match '{2}.'
TestStartupTypeMismatch=Startup type for service '{0}' is '{1}'. It does not match '{2}'.
MethodFailed=The '{0}' method of '{1}' failed with error code: '{2}'.
ErrorChangingProperty=Failed to change '{0}' property. Message: '{1}'
ErrorSetingLogOnAsServiceRightsForUser=Error granting '{0}' the right to log on as a service. Message: '{1}'.
CannotOpenPolicyErrorMessage=Cannot open policy manager
UserNameTooLongErrorMessage=User name is too long
CannotLookupNamesErrorMessage=Failed to lookup user name
CannotOpenAccountErrorMessage=Failed to open policy for user
CannotCreateAccountAccessErrorMessage=Failed to create policy for user
CannotGetAccountAccessErrorMessage=Failed to get user policy rights
CannotSetAccountAccessErrorMessage=Failed to set user policy rights
BinaryPathNotSpecified=Specify the path to the executable when trying to create a new service
ServiceAlreadyExists=The service '{0}' to create already exists
ServiceExistsSamePath=The service '{0}' to create already exists with path '{1}'
ServiceNotExists=The service '{0}' does not exist. Specify the path to the executable to create a new service
ErrorDeletingService=Error in deleting service '{0}'
ServiceDeletedSuccessfully=Service '{0}' Deleted Successfully
TryDeleteAgain=Wait for 2 seconds for a service to get deleted
WritePropertiesIgnored=Service '{0}' already exists. Write properties such as Status, DisplayName, Description, Dependencies will be ignored for existing services.
###PSLOC

'@

