# UpdateRecordRequestInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Id** | **int64** |  | 
**Host** | **string** |  | 
**Type** | **string** |  | 
**Content** | **string** |  | 
**Ttl** | **int64** |  | 
**AliasId** | Pointer to **int64** |  | [optional] 
**LbId** | Pointer to **int64** |  | [optional] 

## Methods

### NewUpdateRecordRequestInner

`func NewUpdateRecordRequestInner(id int64, host string, type_ string, content string, ttl int64, ) *UpdateRecordRequestInner`

NewUpdateRecordRequestInner instantiates a new UpdateRecordRequestInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewUpdateRecordRequestInnerWithDefaults

`func NewUpdateRecordRequestInnerWithDefaults() *UpdateRecordRequestInner`

NewUpdateRecordRequestInnerWithDefaults instantiates a new UpdateRecordRequestInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetId

`func (o *UpdateRecordRequestInner) GetId() int64`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *UpdateRecordRequestInner) GetIdOk() (*int64, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *UpdateRecordRequestInner) SetId(v int64)`

SetId sets Id field to given value.


### GetHost

`func (o *UpdateRecordRequestInner) GetHost() string`

GetHost returns the Host field if non-nil, zero value otherwise.

### GetHostOk

`func (o *UpdateRecordRequestInner) GetHostOk() (*string, bool)`

GetHostOk returns a tuple with the Host field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHost

`func (o *UpdateRecordRequestInner) SetHost(v string)`

SetHost sets Host field to given value.


### GetType

`func (o *UpdateRecordRequestInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *UpdateRecordRequestInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *UpdateRecordRequestInner) SetType(v string)`

SetType sets Type field to given value.


### GetContent

`func (o *UpdateRecordRequestInner) GetContent() string`

GetContent returns the Content field if non-nil, zero value otherwise.

### GetContentOk

`func (o *UpdateRecordRequestInner) GetContentOk() (*string, bool)`

GetContentOk returns a tuple with the Content field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetContent

`func (o *UpdateRecordRequestInner) SetContent(v string)`

SetContent sets Content field to given value.


### GetTtl

`func (o *UpdateRecordRequestInner) GetTtl() int64`

GetTtl returns the Ttl field if non-nil, zero value otherwise.

### GetTtlOk

`func (o *UpdateRecordRequestInner) GetTtlOk() (*int64, bool)`

GetTtlOk returns a tuple with the Ttl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTtl

`func (o *UpdateRecordRequestInner) SetTtl(v int64)`

SetTtl sets Ttl field to given value.


### GetAliasId

`func (o *UpdateRecordRequestInner) GetAliasId() int64`

GetAliasId returns the AliasId field if non-nil, zero value otherwise.

### GetAliasIdOk

`func (o *UpdateRecordRequestInner) GetAliasIdOk() (*int64, bool)`

GetAliasIdOk returns a tuple with the AliasId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAliasId

`func (o *UpdateRecordRequestInner) SetAliasId(v int64)`

SetAliasId sets AliasId field to given value.

### HasAliasId

`func (o *UpdateRecordRequestInner) HasAliasId() bool`

HasAliasId returns a boolean if a field has been set.

### GetLbId

`func (o *UpdateRecordRequestInner) GetLbId() int64`

GetLbId returns the LbId field if non-nil, zero value otherwise.

### GetLbIdOk

`func (o *UpdateRecordRequestInner) GetLbIdOk() (*int64, bool)`

GetLbIdOk returns a tuple with the LbId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLbId

`func (o *UpdateRecordRequestInner) SetLbId(v int64)`

SetLbId sets LbId field to given value.

### HasLbId

`func (o *UpdateRecordRequestInner) HasLbId() bool`

HasLbId returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


