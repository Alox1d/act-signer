#requires -Version 5.1
<#
Managed regression tests for the PowerShell reflection helpers and discovery
error reporting. These tests do not load CryptoPro, use COM, read a certificate
store, access a token, or create/verify an electronic signature.

Run with Windows PowerShell 5.1 or PowerShell 7:
  powershell.exe -NoProfile -File .\ActSigner.CryptoPro.Tests.ps1

Passing on Linux verifies managed argument/collection behavior only. Windows
PowerShell 5.1 with the actual CAdESCOM runtime still needs an integration check.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

if (-not ('ActSignerManagedTests.Collection' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;

namespace ActSignerManagedTests
{
    public sealed class Collection : IEnumerable
    {
        private readonly object[] items;
        public Collection(object[] items) { this.items = items; FindResult = this; }
        public bool ThrowOnEnumeration { get; set; }
        public bool ThrowOnCount { get; set; }
        public int EnumerationCalls { get; private set; }
        public int LastIndex { get; private set; }
        public int FindCalls { get; private set; }
        public int LastFindType { get; private set; }
        public string LastThumbprint { get; private set; }
        public bool LastValidOnly { get; private set; }
        public Collection FindResult { get; set; }
        public int Count
        {
            get
            {
                if (ThrowOnCount) throw new NullReferenceException("Injected Count failure.");
                return items.Length;
            }
        }
        public object this[int index]
        {
            get
            {
                LastIndex = index;
                if (index < 1 || index > items.Length)
                    throw new ArgumentOutOfRangeException("index");
                return items[index - 1];
            }
        }
        public Collection Find(int findType, string thumbprint, bool validOnly)
        {
            FindCalls++;
            LastFindType = findType;
            LastThumbprint = thumbprint;
            LastValidOnly = validOnly;
            return FindResult;
        }
        public IEnumerator GetEnumerator()
        {
            EnumerationCalls++;
            if (ThrowOnEnumeration)
                throw new InvalidOperationException("The helper enumerated the collection.");
            return items.GetEnumerator();
        }
    }

    public sealed class MemberFixture
    {
        public object Certificate { get; set; }
        public Collection Certificates { get; set; }
        public object[] ArrayProperty { get; set; }
        public bool Flag { get; set; }
        public int Number { get; set; }
        public string Text { get; set; }
        public DateTime Timestamp { get; set; }
        public int VoidCalls { get; private set; }
        public int AddCalls { get; private set; }
        public object AddedObject { get; private set; }
        public object[] CapturedArguments { get; private set; }
        public void Void() { VoidCalls++; }
        public void Add(object value) { AddCalls++; AddedObject = value; }
        public object Echo(object value) { return value; }
        public object ReturnNull() { return null; }
        public object[] ReturnArray() { return ArrayProperty; }
        public void Capture(object nullable, bool flag, int number, string text, object[] array)
        {
            CapturedArguments = new object[] { nullable, flag, number, text, array };
        }
    }

    public sealed class Store
    {
        private readonly Collection certificates;
        public Store(Collection certificates) { this.certificates = certificates; }
        public string FailureStage { get; set; }
        public int OpenCalls { get; private set; }
        public int CloseCalls { get; private set; }
        public int OpenKind { get; private set; }
        public string OpenName { get; private set; }
        public int OpenFlags { get; private set; }
        public void Open(int kind, string name, int flags)
        {
            OpenCalls++;
            OpenKind = kind;
            OpenName = name;
            OpenFlags = flags;
            if (FailureStage == "Store.Open")
                throw new NullReferenceException("Injected Open failure.");
        }
        public Collection Certificates
        {
            get
            {
                if (FailureStage == "Store.Certificates")
                    throw new NullReferenceException("Injected Certificates failure.");
                return certificates;
            }
        }
        public void Close() { CloseCalls++; }
    }

    public static class StoreFactory
    {
        public static readonly Queue<Store> Stores = new Queue<Store>();
        public static int CreateCalls;
        public static Store Next()
        {
            CreateCalls++;
            if (Stores.Count == 0)
                throw new InvalidOperationException("Unexpected extra store creation.");
            return Stores.Dequeue();
        }
        public static void Reset() { Stores.Clear(); CreateCalls = 0; }
    }
}
'@
}

Import-Module (Join-Path $PSScriptRoot 'ActSigner.CryptoPro.psm1') -Force -DisableNameChecking
$cryptoModule = Get-Module ActSigner.CryptoPro
if ($null -eq $cryptoModule) { throw 'The CryptoPro module did not load.' }

# Execute assertions inside the module to access its private helpers. Do not
# reimplement the helpers in this test file.
& $cryptoModule {
    $testCount = 0

    function Assert-Managed {
        param([bool]$Condition, [string]$Message)
        if (-not $Condition) { throw ('ASSERTION FAILED: ' + $Message) }
    }

    $fixture = [ActSignerManagedTests.MemberFixture]::new()
    $first = [object]::new()
    $second = [object]::new()
    $third = [object]::new()

    foreach ($size in @(0, 1, 3)) {
        $items = [Array]::CreateInstance([object], $size)
        if ($size -gt 0) { $items[0] = $first }
        if ($size -gt 1) { $items[1] = $second; $items[2] = $third }
        $collection = [ActSignerManagedTests.Collection]::new($items)
        $collection.ThrowOnEnumeration = $true
        $fixture.Certificates = $collection

        $result = Get-ActComProperty $fixture 'Certificates'
        Assert-Managed ([object]::ReferenceEquals($collection, $result)) "Property preserves the $size-item collection object."
        Assert-Managed ($collection.EnumerationCalls -eq 0) 'Property must not invoke IEnumerable.GetEnumerator.'
        Assert-Managed ((Get-ActComProperty $result 'Count') -eq $size) 'Count remains accessible through the returned collection.'

        # Capture the helper's pipeline output too: exactly one collection,
        # including when that collection itself has zero elements.
        $outputItems = @(Get-ActComProperty $fixture 'Certificates')
        Assert-Managed ($outputItems.Count -eq 1) 'Property emits exactly one object.'
        Assert-Managed ([object]::ReferenceEquals($collection, $outputItems[0])) 'Pipeline output contains the collection itself.'

        $found = Invoke-ActComMethod $collection 'Find' @([int]0, 'TEST-THUMBPRINT', $false)
        Assert-Managed ([object]::ReferenceEquals($collection, $found)) "Find preserves the $size-item collection object."
        Assert-Managed ($collection.EnumerationCalls -eq 0) 'Find must not enumerate its return value.'
        Assert-Managed ($collection.FindCalls -eq 1) 'Find is called exactly once.'
        Assert-Managed ($collection.LastFindType -eq 0 -and $collection.LastThumbprint -eq 'TEST-THUMBPRINT' -and -not $collection.LastValidOnly) 'Find receives int/string/bool values without coercion or reordering.'

        if ($size -gt 0) {
            $item = Get-ActComProperty $found 'Item' @([int]1)
            Assert-Managed ([object]::ReferenceEquals($first, $item)) 'Indexed Item returns the original first element.'
            Assert-Managed ($collection.LastIndex -eq 1) 'Indexed Item uses the original one-based index.'
            if ($size -eq 3) {
                $item = Get-ActComProperty $found 'Item' @([int]3)
                Assert-Managed ([object]::ReferenceEquals($third, $item)) 'Indexed Item can retrieve the final element.'
            }
        }
        $testCount++
        Write-Host "PASS collection property/Find/Item: size $size"
    }

    # SetProperty's @(,$Value) must supply one argument, not wrap the actual
    # object in another array, even when the object itself is enumerable.
    foreach ($value in @($first, $collection)) {
        $setterOutput = @(Set-ActComProperty $fixture 'Certificate' $value)
        Assert-Managed ($setterOutput.Count -eq 0) 'A property setter does not emit output.'
        Assert-Managed ([object]::ReferenceEquals($value, $fixture.Certificate)) 'Object setter preserves reference identity without an array wrapper.'
    }

    $payload = [object[]]@($first, [int]7, 'payload')
    Set-ActComProperty $fixture 'Certificate' $payload
    Assert-Managed ([object]::ReferenceEquals($payload, $fixture.Certificate)) 'Object setter preserves an object[] value as one argument.'
    Set-ActComProperty $fixture 'ArrayProperty' $payload
    Assert-Managed ([object]::ReferenceEquals($payload, $fixture.ArrayProperty)) 'Array-typed setter preserves the original array.'
    Set-ActComProperty $fixture 'Certificate' $null
    Assert-Managed ($null -eq $fixture.Certificate) 'Object setter accepts an explicit null.'
    Set-ActComProperty $fixture 'Flag' $false
    Set-ActComProperty $fixture 'Number' ([int]0)
    Set-ActComProperty $fixture 'Text' ''
    $date = [DateTime]::new(2026, 10, 12, 1, 2, 3)
    Set-ActComProperty $fixture 'Timestamp' $date
    Assert-Managed (-not $fixture.Flag -and $fixture.Number -eq 0 -and $fixture.Text -ceq '') 'False/zero/empty string setters do not lose values.'
    Assert-Managed ($fixture.Timestamp -eq $date) 'DateTime setter preserves the date value.'
    $testCount++
    Write-Host 'PASS property setters: references, arrays, null, scalar values, DateTime'

    # Use the exact Add call-site argument packaging present in the application.
    foreach ($attribute in @($first, $collection)) {
        $voidResult = Invoke-ActComMethod $fixture 'Add' @(,$attribute)
        Assert-Managed ($null -eq $voidResult) 'Void Add returns null.'
        Assert-Managed ([object]::ReferenceEquals($attribute, $fixture.AddedObject)) 'Add receives the object itself, not a one-element wrapper array.'
    }
    $voidResult = Invoke-ActComMethod $fixture 'Add' @(,$payload)
    Assert-Managed ([object]::ReferenceEquals($payload, $fixture.AddedObject)) 'Add can receive an array as its one object argument.'
    $voidResult = Invoke-ActComMethod $fixture 'Add' @(,$null)
    Assert-Managed ($null -eq $fixture.AddedObject) 'Add accepts an explicit single null argument.'
    Assert-Managed ($fixture.AddCalls -eq 4) 'Each Add call executes once.'
    $voidResult = Invoke-ActComMethod $fixture 'Void'
    Assert-Managed ($fixture.VoidCalls -eq 1 -and $null -eq $voidResult) 'Zero-argument void method executes once.'
    $testCount++
    Write-Host 'PASS void methods and single-object Add arguments'

    $mixedArguments = [Array]::CreateInstance([object], 5)
    $mixedArguments[0] = $null
    $mixedArguments[1] = $true
    $mixedArguments[2] = [int]42
    $mixedArguments[3] = 'A&B (test)'
    $mixedArguments[4] = $payload
    [void](Invoke-ActComMethod $fixture 'Capture' $mixedArguments)
    Assert-Managed ($fixture.CapturedArguments.Length -eq 5) 'Mixed argument count is preserved.'
    Assert-Managed ($null -eq $fixture.CapturedArguments[0]) 'Null argument position is preserved.'
    Assert-Managed ($fixture.CapturedArguments[1] -is [bool] -and $fixture.CapturedArguments[1]) 'Boolean argument type/value is preserved.'
    Assert-Managed ($fixture.CapturedArguments[2] -is [int] -and $fixture.CapturedArguments[2] -eq 42) 'Integer argument type/value is preserved.'
    Assert-Managed ($fixture.CapturedArguments[3] -ceq 'A&B (test)') 'String content is preserved.'
    Assert-Managed ([object]::ReferenceEquals($payload, $fixture.CapturedArguments[4])) 'Nested array argument preserves its identity and position.'
    $echo = Invoke-ActComMethod $fixture 'Echo' @(,$collection)
    Assert-Managed ([object]::ReferenceEquals($collection, $echo)) 'Method returning object preserves an IEnumerable instance.'
    $nullResult = Invoke-ActComMethod $fixture 'ReturnNull'
    Assert-Managed ($null -eq $nullResult) 'Null method result remains null.'
    foreach ($arraySize in @(0, 1, 3)) {
        $returnedArray = [Array]::CreateInstance([object], $arraySize)
        if ($arraySize -gt 0) { $returnedArray[0] = $first }
        $fixture.ArrayProperty = $returnedArray
        $fromProperty = Get-ActComProperty $fixture 'ArrayProperty'
        $fromMethod = Invoke-ActComMethod $fixture 'ReturnArray'
        Assert-Managed ([object]::ReferenceEquals($returnedArray, $fromProperty)) 'Array property is not flattened or copied.'
        Assert-Managed ([object]::ReferenceEquals($returnedArray, $fromMethod)) 'Array method result is not flattened or copied.'
    }
    $testCount++
    Write-Host 'PASS argument types/positions and null/array method results'

    # Exercise the real discovery function with managed stores that fail at
    # each outer stage. No fake signatures, user certificates or private keys.
    $originalFactory = (Get-Item Function:New-ActComObject).ScriptBlock
    try {
        Set-Item Function:script:New-ActComObject -Value {
            param([string]$ProgId)
            if ($ProgId -ne 'CAdESCOM.Store') { throw 'Unexpected test ProgID.' }
            $store = [ActSignerManagedTests.StoreFactory]::Next()
            return ,$store
        }

        foreach ($failureStage in @('Store.Open', 'Store.Certificates', 'Certificates.Count')) {
            $badCollection = [ActSignerManagedTests.Collection]::new([object[]]@())
            $badCollection.ThrowOnEnumeration = $true
            $badCollection.ThrowOnCount = $failureStage -eq 'Certificates.Count'
            $badStore = [ActSignerManagedTests.Store]::new($badCollection)
            $badStore.FailureStage = $failureStage
            $goodCollection = [ActSignerManagedTests.Collection]::new([object[]]@())
            $goodCollection.ThrowOnEnumeration = $true
            $goodStore = [ActSignerManagedTests.Store]::new($goodCollection)

            [ActSignerManagedTests.StoreFactory]::Reset()
            [ActSignerManagedTests.StoreFactory]::Stores.Enqueue($badStore)
            [ActSignerManagedTests.StoreFactory]::Stores.Enqueue($goodStore)
            $discovery = Get-ActCertificates

            Assert-Managed ($discovery.Certificates.Count -eq 0) 'A failing/empty store pair does not invent certificates.'
            Assert-Managed ([ActSignerManagedTests.StoreFactory]::CreateCalls -eq 2) 'Discovery continues to the second store after an error.'
            Assert-Managed ($badStore.OpenKind -eq 100 -and $goodStore.OpenKind -eq 2) 'Discovery retains container/current-user store kinds.'
            Assert-Managed ($badStore.OpenName -ceq 'My' -and $goodStore.OpenName -ceq 'My' -and $badStore.OpenFlags -eq 0 -and $goodStore.OpenFlags -eq 0) 'Discovery preserves store names and read-only flags.'
            $failureWarnings = @($discovery.Warnings | Where-Object { $_ -like '*Injected*failure*' })
            Assert-Managed ($failureWarnings.Count -eq 1) 'The injected store error is visible once.'
            Assert-Managed ($failureWarnings[0].Contains($failureStage)) 'Error includes the precise failed stage.'
            Assert-Managed ($failureWarnings[0] -match '0x80004003') 'Error preserves the original NullReference HRESULT.'
            Assert-Managed ($failureWarnings[0] -match 'NullReferenceException') 'Error preserves the original exception type.'
            Assert-Managed ($goodStore.CloseCalls -eq 1) 'A successfully opened store is closed.'
            $expectedBadCloseCount = if ($failureStage -eq 'Store.Open') { 0 } else { 1 }
            Assert-Managed ($badStore.CloseCalls -eq $expectedBadCloseCount) 'Cleanup closes the failed store only if it opened.'
            Assert-Managed ($badCollection.EnumerationCalls -eq 0 -and $goodCollection.EnumerationCalls -eq 0) 'Discovery never enumerates collection objects implicitly.'
            $testCount++
            Write-Host "PASS discovery error reporting and cleanup: $failureStage"
        }
    }
    finally {
        Set-Item Function:script:New-ActComObject -Value $originalFactory
        [ActSignerManagedTests.StoreFactory]::Reset()
    }

    Write-Host ("PASS: {0} managed regression groups. Real Windows COM/CryptoPro integration was not exercised." -f $testCount)
}
