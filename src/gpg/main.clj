(ns gpg.main
  (:import [org.apache.commons.io FileUtils])
  (:use [gpg.core]
        [clojure.java.io]
        [me.raynes.fs.compression]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def file-private (file "C:/Users/BlindingDark/Desktop/private.txt"))
(def file-public (file "C:/Users/BlindingDark/Desktop/public.txt"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;发送方的中间文件
;mail文件
(def file-mail (file "C:/Users/BlindingDark/Desktop/send/mail.txt"))
;hash摘要文件
(def file-hash (file "C:/Users/BlindingDark/Desktop/send/hash.txt"))
(def file-signed-hash (file "C:/Users/BlindingDark/Desktop/send/signed-hash.txt"))

;mail-hash压缩文件
(def file-hash-mail-zip (file "C:/Users/BlindingDark/Desktop/send/hash-mail.zip"))

(def file-hash-mail-BASE64ed (file "C:/Users/BlindingDark/Desktop/send/hash-mail-zip-BASE64.txt"))

(def file-hash-mail-encrypted (file "C:/Users/BlindingDark/Desktop/send/hash-mail-encrypted.txt"))

(def file-DES-key (file "C:/Users/BlindingDark/Desktop/send/DES-key.txt"))
(def file-DES-key-encrypted (file "C:/Users/BlindingDark/Desktop/send/DES-key-encrypted.txt"))


(def file-mail-ready-zip (file "C:/Users/BlindingDark/Desktop/send/mail-ready.zip"))
(def file-send (file "C:/Users/BlindingDark/Desktop/send/send.txt"))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;接受方的中间文件

(def file-receive file-send)
(def file-mail-zip (file "C:/Users/BlindingDark/Desktop/rec/mail-receive.zip"))

(def file-DES-key-encrypted-rec (file "C:/Users/BlindingDark/Desktop/rec/DES-key-encrypted.txt"))
(def file-hash-mail-encrypted-rec (file "C:/Users/BlindingDark/Desktop/rec/hash-mail-encrypted.txt"))

(def file-DES-key-rec (file "C:/Users/BlindingDark/Desktop/rec/DES-key-rec.txt"))

(def file-hash-mail-BASE64ed-rec (file "C:/Users/BlindingDark/Desktop/rec/hash-mail-zip-BASE64.txt"))

(def file-hash-mail-zip-rec (file "C:/Users/BlindingDark/Desktop/rec/hash-mail.zip"))

(def file-signed-hash-rec (file "C:/Users/BlindingDark/Desktop/rec/signed-hash.txt"))

(def file-mail-rec (file "C:/Users/BlindingDark/Desktop/rec/mail.txt"))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;创建新的RSA-key-pair
;(save-key-pair (generate-RSA-key-pair) "C:/Users/BlindingDark/Desktop")

;; 创建hash文件。base64编码再保存,file-mail为mail文件,file-hash为摘要文件
(creat-hash-file file-mail file-hash)


;RSA加密（签名）hash文件;用私钥加密（签名）hash文件
(spit file-signed-hash (RSA-encrypt-by-private-key (slurp file-private) (slurp file-hash)))


;压缩
(zip-2-files file-hash-mail-zip file-mail file-signed-hash)

;zip编码base64,保存为txt
(spit file-hash-mail-BASE64ed (BASE64-encoder (FileUtils/readFileToByteArray file-hash-mail-zip)))


;一次性密钥加密
(let [DES-key (generate-random-DES-key)]
  (spit file-hash-mail-encrypted (DES-encrypt-string (second DES-key) (slurp file-hash-mail-BASE64ed)))
  (spit file-DES-key (first DES-key)))

;用公钥对DES-key加密（保密）
(spit file-DES-key-encrypted (RSA-encrypt-by-public-key (slurp file-public) (slurp file-DES-key)))

;压缩
(zip-2-files file-mail-ready-zip file-hash-mail-encrypted file-DES-key-encrypted)
;zip编码base64,保存为txt
(spit file-send (BASE64-encoder (FileUtils/readFileToByteArray file-mail-ready-zip)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;解码发来的Email
(copy (BASE64-decoder (slurp file-receive)) file-mail-zip)
;解压
(unzip file-mail-zip (.getParent file-mail-zip))
;用私钥解密DES-key
(spit file-DES-key-rec (RSA-decrypt-by-private-key (slurp file-private) (slurp file-DES-key-encrypted-rec)))


;用一次性密钥解密
(spit file-hash-mail-BASE64ed-rec (DES-decrypt-string (generate-DES-key (slurp file-DES-key-rec)) (slurp file-hash-mail-encrypted-rec)))

;解码zip的base64
(copy (BASE64-decoder (slurp file-hash-mail-BASE64ed-rec)) file-hash-mail-zip-rec)

;解压
(unzip file-hash-mail-zip-rec (.getParent file-hash-mail-zip-rec))


;判断是否是本人
(=
  ;计算hash
  (BASE64-encoder (md5-result file-mail-rec))
  ;用对方公钥解密signed-hash
  (RSA-decrypt-by-public-key (slurp file-public) (slurp file-signed-hash-rec)))
