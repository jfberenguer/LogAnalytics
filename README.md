# MICROSOFT IGNITE 2018
# THR3115 - Azure Log Analytics: Deep dive into the Azure Kusto query language

Sample Kusto queries used during the session THR3115 - Azure Log Analytics: Deep dive into the Azure Kusto query language at Ignite in Orlando the 24th of September 2018.

Feel free to use and send comments or questions.

In order to use in your environment, it's necessary to modify time range and names for servers and users.

Most of examples are based on the detction of Event ID 4625 : authentication error.
To collect this event, you'll have to configure Azure Security Center policy Data collection, in order to activate Windows security events (common level)


//the first request

//Search in a specific  table

//Change Time Range

search in (SecurityEvent) "An account failed to log on"


//Use wild cards
search in (SecurityEvent) "demo*"

//add top 20
search in (SecurityEvent) "An account failed to log on"
|take 20

//Sort by TimeGenerated
search in (SecurityEvent) "An account failed to log on"
|take 20
|sort by TimeGenerated desc


//Filter on last 7 days, using ago
//Use of a string operator
//many others are available
SecurityEvent 
|where TimeGenerated >= ago(7d)
|where Computer contains "xxx" 
|where EventID == 4625


//Filter on a specific time range, using between
SecurityEvent 
|where TimeGenerated between (datetime(2018-09-01) .. datetime(2018-10-31))
|where Computer contains "xxx" 
|where EventID == 4625



//What are the login used : use of Aggregations
SecurityEvent 
|where TimeGenerated between (datetime(2018-09-01) .. datetime(2018-10-31))
|where Computer contains "sec" 
|where EventID == 4625
|summarize count() by Account
|order by count_ desc


//What is the top 10 of login used 
SecurityEvent 
|where TimeGenerated between (datetime(2018-09-01) .. datetime(2018-10-31))
|where Computer contains "xxx" 
|where EventID == 4625
|summarize count() by Account
|order by count_ desc 
|take 10



//Graph to show the most used login and Pin to dashboard
SecurityEvent 
|where TimeGenerated > ago(7d)
|where Computer contains "xxx" 
|where EventID == 4625
|summarize count() by Account | render timechart


//Graph showing, by day, the number of login failed for the last 2 weeks
// For continuous values like times or numbers, 
//It’s better to break the range into manageable units, using bin
SecurityEvent 
|where TimeGenerated > ago(14d)
|where EventID == 4625
|summarize count() by tostring(EventID), bin(TimeGenerated, 1d)
| render barchart


//Select columns to display with Project
SecurityEvent 
|where EventID == 4624 and Account contains "xxx" 
|project Computer, Account, TimeGenerated


//Pass the time range in parameter 
//Use of LET to assign results to a variable, 
//and refer to it later in the query:
//Rename the column and convert Time Generated (UTC) in local time
let startDatetime = todatetime("2018-07-01 00:00:00");
let endDatetime = todatetime("2018-09-30 00:00:00");
SecurityEvent 
|where EventID == 4624 and Account contains "xxx" 
| where TimeGenerated between(startDatetime .. endDatetime)
|project Computer, Account, Time = TimeGenerated + 2h

//Aggregation – generating a list
SecurityEvent 
| where TimeGenerated > ago(14d)
| order by TimeGenerated desc
| summarize makelist(EventID) by Computer

//Aggregation – create a list of distinct values
SecurityEvent 
| where TimeGenerated > ago(14d)
| order by TimeGenerated desc
| summarize makeset(EventID) by Computer


// Identify if there is a brute force attack on a computer with needed updates
//First: Obtain the list of Title Updates security needed and on which computer 
Update
|where TimeGenerated >= ago(100d)  
|where UpdateState has "Needed" and Title contains "security" 
 |summarize Computer=makeset(Computer) by Title

//Second: check if there are brute force attacks
SecurityDetection
|where TimeGenerated >= ago(100d)  
| where Description contains "brute force attack" 

// Merge the two, using a function for the first
//Let statements can also take input parameters, 
//providing a way to write reusable functions.
let machinesWithBruteForceAttack = (){ 
    Update
        |where TimeGenerated >= ago(100d)  
        |where UpdateState has "Needed" and Title contains "KB2267602" 
        |summarize Computer=makeset(Computer)
};
SecurityDetection
|where TimeGenerated >= ago(100d)  
| where Description contains "brute force attack" 
| where Computer in (machinesWithBruteForceAttack) //in clause to limit us to just these computers
| summarize by Computer


//On the past 2 weeks, are they any success and failed logon for a same account on a same computer
// Use of joins for cross analysis
SecurityEvent 
|where TimeGenerated >= ago(100d)  
| where EventID == 4624 and Account has "xxx" and Computer contains "yyy" 
|top 1 by TimeGenerated 
| project Computer, SuccessAccount=Account , LastSuccessLogonTime=TimeGenerated
| join kind= inner (
    SecurityEvent 
    |where TimeGenerated >= ago(100d)
    | where EventID == 4625 and Account has "xxx" and Computer contains "yyy" 
    | top 1 by TimeGenerated 
    | project Computer, FailedAccount=Account, LastFailedLogonTime=TimeGenerated
) on Computer  


//another useful request: 
//Duration between logon and logoff for a specific User
SecurityEvent 
| where EventID == 4624 and Account contains "xxx" 
| where TimeGenerated >= ago(100d)
| project Computer, Account, TargetLogonId, LogonTime=TimeGenerated
| join kind= inner (
    SecurityEvent 
    | where EventID == 4634 and Account contains "xxx" 
    |where TimeGenerated >= ago(100d)
    | project TargetLogonId, LogoffTime=TimeGenerated
) on TargetLogonId
| extend Duration = LogoffTime-LogonTime
| project-away TargetLogonId1 
| top 10 by Duration desc


//use of a ref table
//to transform in a more presentable way
//Example with Login event ID
let DimTable = datatable(EventID:int, eventName:string)
  [
    4624, "User say Hello",
    4625, "Warning - a user is trying to connect",
    4634, "USer say Bye bye" 
  ];
SecurityEvent
|where TimeGenerated >= ago(14d) 
| join kind = inner
 DimTable on EventID
| summarize count() by eventName


//Focus on root cause analysis with smart analytic
//When result contains many rows, it’s difficult 
//to understand and use it to build the next step
//Autocluster take all data, and classify it into clusters to outline the results
//High level and diverged cluster
// cluster 1 : Account \administrator
// cluster 2 : Account \ADMINISTRATOR
// Cluster 3 : IP Address 
SecurityEvent 
|where EventID == 4625
|where Computer contains "xxx" 
| evaluate autocluster_v2()



//Smart analytic with “basket”
//Based on machine learning apriori algorithm
//Use to find the most frequent patterns
//based on a threshold to set the minimal ratio of rows considered as frequent
let threshold = 0.01;
SecurityEvent
|where TimeGenerated between (datetime(2018-08-01) .. datetime(2018-08-31))
|where Computer contains "xxx" and Activity contains "4625" 
| project Account, Computer, Activity, LogonTypeName, IpAddress 
| evaluate basket(threshold)



//Smart analytic with diffpatern – diagnose by comparison
//Juxtapose two behaviors, and discover the differences between them
//compare success and failed logon
SecurityEvent
| where TimeGenerated >= ago(14d) and EventID == 4624 or EventID == 4625
| project Account, Computer, EventID, Activity
| evaluate diffpatterns(EventID, "4624", "4625")

Event
| where TimeGenerated >= ago(7d)
and EventLevelName == "Warning" or EventLevelName == "Error"
| project Source, Computer, EventID , EventCategory, EventLevelName 
| evaluate diffpatterns(EventLevelName, "Warning", "Error")
|project-rename Errors = CountA, Warnings = CountB, ErrorPercent = PercentA, WarningPercent = PercentB, PercentDiff = PercentDiffAB



//Export to power BI
//create a txt file, 
// connect to power BI
//get data -> black -> advanced editor
//Copy - paste the txt
Perf 
| where ObjectName == "Processor" 
| where CounterName == "% Processor Time" 
| summarize avg(CounterValue) by Computer, TimeGenerated | render timechart



//Create an alert
SecurityEvent 
|where TimeGenerated >= ago(1d) 
|where EventID == 4625






@jfberenguer
Commit new file
Commit summary 
README.md
Optional extended description
README.md
 
© 2019 GitHub, Inc.
Terms
Privacy
Security
Status
Help
Contact GitHub
Pricing
API
Training
Blog
About
