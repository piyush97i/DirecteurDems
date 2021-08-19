package service

import (
  "fmt"
  "github.com/jumpserver/koko/pkg/logger"
)

func GetData()(bodyMap map[string]string){
  _, err := authClient.Get(GetAlertEmailAddressURL,&bodyMap)
  if err != nil {
    fmt.Println("根据URL = " + GetAlertEmailAddressURL + "获取到的告警邮件地址信息时，出错了 = ",err)
    logger.Error("根据URL = " + GetAlertEmailAddressURL + "获取到的告警邮件地址信息时，出错了 = ",err)
  }
  return
}
