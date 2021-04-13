package netlinktc

import (
	"net"

	"github.com/vishvananda/netlink"
)

type AdqtcAddFilterRequest struct {
	CreateFilterFunc FilterGenerator
	Filter           AdqFilter
}

type NetlinkTcMock struct {
	AdqTCInitError       error
	InitMaster           string
	NumTC                uint8
	SharedTCNum          uint8
	SharedTCErr          error
	StartQ               uint16
	StopQ                uint16
	StartStopErr         error
	AddFilterReqests     []AdqtcAddFilterRequest
	AddFilterErr         error
	DelFiletrsRequests   []net.IP
	DelFlowerRequests    []net.IP
	DeletedFlowerFilters []*netlink.Flower
	DelFlowerErr         error
	DelU32Requests       []*netlink.Flower
	DelU32Err            error
	DelFiltersErr        error
	GetFlowerFilters     []*netlink.Flower
	GetFlowerFiltersErr  error
	GetU32Filters        []*netlink.U32
	GetU32FiltersErr     error
}

func (ntc *NetlinkTcMock) GetNumTC() uint8 {
	return ntc.NumTC
}

func (ntc *NetlinkTcMock) GetSharedTC() (uint8, error) {
	return ntc.SharedTCNum, ntc.SharedTCErr
}

func (ntc *NetlinkTcMock) TCGetStartStopQ(tc uint8) (uint16, uint16, error) {
	return ntc.StartQ, ntc.StopQ, ntc.StartStopErr
}

func (ntc *NetlinkTcMock) TCAddFilter(createFilterFunc FilterGenerator, filter AdqFilter) error {
	ntc.AddFilterReqests = append(ntc.AddFilterReqests, AdqtcAddFilterRequest{
		CreateFilterFunc: createFilterFunc,
		Filter:           filter,
	})
	return ntc.AddFilterErr
}

func (ntc *NetlinkTcMock) TCDelFilters(ip net.IP) error {
	ntc.DelFiletrsRequests = append(ntc.DelFiletrsRequests, ip)
	return ntc.DelFiltersErr
}

func (ntc *NetlinkTcMock) TCGetFilters() ([]*netlink.Flower, error) {
	return ntc.GetFlowerFilters, ntc.GetFlowerFiltersErr
}

func (ntc *NetlinkTcMock) TCDelFlowerFilters(ip net.IP) ([]*netlink.Flower, error) {
	ntc.DelFlowerRequests = append(ntc.DelFlowerRequests, ip)
	return ntc.DeletedFlowerFilters, ntc.DelFlowerErr
}

func (ntc *NetlinkTcMock) TCGetFlowerFilters() ([]*netlink.Flower, error) {
	return ntc.GetFlowerFilters, ntc.GetFlowerFiltersErr
}

func (ntc *NetlinkTcMock) TCGetU32Filters() ([]*netlink.U32, error) {
	return ntc.GetU32Filters, ntc.GetU32FiltersErr
}

func (ntc *NetlinkTcMock) TCDelMatchingU32Filters(flower []*netlink.Flower) error {
	ntc.DelU32Requests = flower
	return ntc.DelU32Err
}
