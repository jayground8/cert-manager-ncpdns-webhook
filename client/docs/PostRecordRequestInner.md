# PostRecordRequestInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Host** | **string** |  | 
**Type** | **string** |  | 
**Content** | **string** |  | 
**Ttl** | **int64** |  | 
**AliasId** | Pointer to **int64** |  | [optional] 
**LbId** | Pointer to **int64** |  | [optional] 

## Methods

### NewPostRecordRequestInner

`func NewPostRecordRequestInner(host string, type_ string, content string, ttl int64, ) *PostRecordRequestInner`

NewPostRecordRequestInner instantiates a new PostRecordRequestInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPostRecordRequestInnerWithDefaults

`func NewPostRecordRequestInnerWithDefaults() *PostRecordRequestInner`

NewPostRecordRequestInnerWithDefaults instantiates a new PostRecordRequestInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetHost

`func (o *PostRecordRequestInner) GetHost() string`

GetHost returns the Host field if non-nil, zero value otherwise.

### GetHostOk

`func (o *PostRecordRequestInner) GetHostOk() (*string, bool)`

GetHostOk returns a tuple with the Host field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHost

`func (o *PostRecordRequestInner) SetHost(v string)`

SetHost sets Host field to given value.


### GetType

`func (o *PostRecordRequestInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *PostRecordRequestInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *PostRecordRequestInner) SetType(v string)`

SetType sets Type field to given value.


### GetContent

`func (o *PostRecordRequestInner) GetContent() string`

GetContent returns the Content field if non-nil, zero value otherwise.

### GetContentOk

`func (o *PostRecordRequestInner) GetContentOk() (*string, bool)`

GetContentOk returns a tuple with the Content field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetContent

`func (o *PostRecordRequestInner) SetContent(v string)`

SetContent sets Content field to given value.


### GetTtl

`func (o *PostRecordRequestInner) GetTtl() int64`

GetTtl returns the Ttl field if non-nil, zero value otherwise.

### GetTtlOk

`func (o *PostRecordRequestInner) GetTtlOk() (*int64, bool)`

GetTtlOk returns a tuple with the Ttl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTtl

`func (o *PostRecordRequestInner) SetTtl(v int64)`

SetTtl sets Ttl field to given value.


### GetAliasId

`func (o *PostRecordRequestInner) GetAliasId() int64`

GetAliasId returns the AliasId field if non-nil, zero value otherwise.

### GetAliasIdOk

`func (o *PostRecordRequestInner) GetAliasIdOk() (*int64, bool)`

GetAliasIdOk returns a tuple with the AliasId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAliasId

`func (o *PostRecordRequestInner) SetAliasId(v int64)`

SetAliasId sets AliasId field to given value.

### HasAliasId

`func (o *PostRecordRequestInner) HasAliasId() bool`

HasAliasId returns a boolean if a field has been set.

### GetLbId

`func (o *PostRecordRequestInner) GetLbId() int64`

GetLbId returns the LbId field if non-nil, zero value otherwise.

### GetLbIdOk

`func (o *PostRecordRequestInner) GetLbIdOk() (*int64, bool)`

GetLbIdOk returns a tuple with the LbId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLbId

`func (o *PostRecordRequestInner) SetLbId(v int64)`

SetLbId sets LbId field to given value.

### HasLbId

`func (o *PostRecordRequestInner) HasLbId() bool`

HasLbId returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


