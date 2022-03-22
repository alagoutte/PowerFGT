---
external help file: PowerFGT-help.xml
Module Name: PowerFGT
online version:
schema: 2.0.0
---

# Remove-FGTSystemInterfaceMember

## SYNOPSIS
Remove a FortiGate Interface Member

## SYNTAX

```
Remove-FGTSystemInterfaceMember [-interface] <PSObject> [-allowaccess <String[]>] [-vdom <String[]>]
 [-connection <PSObject>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Remove a FortiGate Interface Member (allowaccess)

## EXAMPLES

### EXAMPLE 1
```
$MyFGTInterface = Get-FGTSystemInterface -name PowerFGT
PS C:\>$MyFGTInterface | Remove-FGTSystemInterfaceMember -allowaccess ssh
```

Remove ssh to allowaccess for MyFGTInterface

### EXAMPLE 2
```
$MyFGTInterface = Get-FGTSystemInterface -name PowerFGT
PS C:\>$MyFGTInterface | Remove-FGTSystemInterfaceMember -allowaccess ssh, https
```

Remove ssh and https to allowaccess for MyFGTInterface

## PARAMETERS

### -interface
{{ Fill interface Description }}

```yaml
Type: PSObject
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -allowaccess
{{ Fill allowaccess Description }}

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -vdom
{{ Fill vdom Description }}

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -connection
{{ Fill connection Description }}

```yaml
Type: PSObject
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: $DefaultFGTConnection
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS