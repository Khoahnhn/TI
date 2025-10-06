grammar Grammar;
prog: expression;

// Begin Parser

compareNumber:
    left=Fields_number op=(OperatorNumber|OperatorEqual) right=Number
    ;

compareString:
	left=Fields_string op=(OperatorContain|OperatorEqual) right=STRING_VALUE
    ;

compareDate:
	left='created_date' op=(OperatorNumber|OperatorEqual) right=STRING_VALUE
    ;

compareBoolean:
	left=Fields_boolean op=OperatorEqual right=Boolean
    ;

compareSeverity:
    left='severity' op=OperatorEqual right=Severity
    ;

compareStatus:
    left='status' op=OperatorEqual right=Status
    ;

compareCategory:
    left='category' op=OperatorEqual right=(
        'vulnerability'
        | 'malware'
        | 'impersonate'
        | 'phishing'
        | 'impersonate_social'
        | 'targeted_vulnerability'
        | 'open_port_anomaly'
        | 'compromised_system'
        | 'deface_attack'
        | 'leak'
    )
    ;

compareFeature:
    left='feature' op=OperatorEqual right=(
        'vulnerability'
        | 'malware'
        | 'brand_abuse'
        | 'compromised_system'
        | 'targeted_vulnerability'
        | 'data_leakage'
    )
    ;

expression
    : left=expression op=Logic right=expression
    | '(' inner=expression ')'
    | compareNumber
    | compareString
    | compareSeverity
    | compareDate
    | compareStatus
    | compareBoolean
    | compareCategory
    | compareFeature
    ;

// Begin Lexer

Number:
    [0-9]+
    ;

STRING_VALUE
    :   '"' ( '\\'. | '""' | ~('"'| '\\') )* '"'
    |   '\'' ('\\'. | '\'\'' | ~('\'' | '\\'))* '\''
    | '"' ('""'|~'"')* '"'
    ;

Logic:
    AND | OR
    ;

AND: 'AND';
OR: 'OR';

Boolean:
    TRUE | FALSE
    ;

TRUE: 'true';
FALSE: 'false';

Whitespace:
    [ \r\n\t]+ -> skip
    ;

Fields_boolean:
	'private'
    ;

Fields_string:
    'id' | 'title' | 'source' | 'created_date'| 'id_alert'
    ;

Fields_number:
    'assess' | 'created_time'
    ;

OperatorContain:
	'!~'|'~'|'^'|'$'
;
OperatorEqual:
	'!='|'='
;

OperatorNumber:
	'>='|'<='|'<'|'>'
;

Function:
	Term | In | Notin
;

Term:
	'TERM('STRING_VALUE')'
;

In:
	'IN('Array')'
;

Notin:
	'NOTIN('Array')'
;

InContain:
	'IN('ArrayString')'
;

NotinContain:
	'NOTIN('ArrayString')'
;

InIp:
	'IN('ArrayIpString')'
;

NotinIp:
	'NOTIN('ArrayIpString')'
;

Severity
    : 'low'
    | 'medium'
    | 'high'
    | 'critical'
    ;

Status
    : 'opened'
    | 'closed'
    | 'false_positive'
    ;


ValueIpString:
	Ip_string | Ip_value;

Ip_string:
	'"' Ip_byte '.' Ip_byte '.' Ip_byte '.' Ip_byte ('/' ( ('0'..'9') | ('1'..'3')('0'..'9') ))? '"'
;

Ip_byte:
	('0'..'9') | ('1'..'9')('0'..'9') | ('1'..'9')('0'..'9')('0'..'9')
;

Ip_value:
	Ip_byte '.' Ip_byte '.' Ip_byte '.' Ip_byte ('/' ( ('0'..'9') | ('1'..'3')('0'..'9') ))?
;

Array:
	'[' (STRING_VALUE | Number)? (',' STRING_VALUE | Number)* ']';

ArrayString:
	'[' (STRING_VALUE)? (',' STRING_VALUE)* ']';

ArrayIpString:
	'[' (ValueIpString)? (',' ValueIpString)* ']';

Literal:
	'TRUE'|'FALSE'
;

NullValue:
	'NULL'
;