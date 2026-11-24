export const th = {
  attachmentCollector: {
    confirm: 'คุณต้องการรวบรวมไฟล์แนบสำหรับโน้ตทั้งหมดในโฟลเดอร์ต่อไปนี้แบบเรียกซ้ำหรือไม่?\n{{folders}}\nการดำเนินการนี้ไม่สามารถยกเลิกได้',
    progressBar: {
      message: 'กำลังรวบรวมไฟล์แนบ {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'กำลังรวบรวมไฟล์แนบ...'
    }
  },
  buttons: {
    copy: 'คัดลอก',
    move: 'ย้าย',
    previewAttachmentFile: 'ดูตัวอย่างไฟล์แนบ',
    skip: 'ข้าม'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'ไฟล์แนบ {{attachment}} ถูกอ้างอิงโดยหลายโน้ต',
    heading: 'กำลังรวบรวมไฟล์แนบที่ใช้โดยหลายโน้ต',
    noPriorityWinnerReason: {
      EmptyList: 'ไม่ได้ย้ายเพราะการตั้งค่า {{settingName}} ว่างเปล่า จึงไม่มีสิ่งใดตัดสินว่าโน้ตใดในเหล่านี้เป็นเจ้าของ',
      NoMatch: 'ไม่ได้ย้ายเพราะไม่มีโน้ตใดในเหล่านี้ตรงกับรายการใดในการตั้งค่า {{settingName}}',
      Tie: 'ไม่ได้ย้ายเพราะมีโน้ตหลายรายการตรงกับการตั้งค่า {{settingName}} เท่ากัน จึงไม่ได้ระบุเจ้าของเพียงรายเดียว'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'ใช้การดำเนินการเดียวกันสำหรับไฟล์แนบที่มีปัญหาอื่น ๆ'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'รวบรวมไฟล์แนบในโฟลเดอร์ปัจจุบัน',
    collectAttachmentsCurrentNote: 'รวบรวมไฟล์แนบในโน้ตปัจจุบัน',
    collectAttachmentsEntireVault: 'รวบรวมไฟล์แนบในคลังข้อมูลทั้งหมด'
  },
  links: {
    documentation: 'เอกสาร',
    tokens: 'โทเคน'
  },
  menuItems: {
    collectAttachmentsInFile: 'รวบรวมไฟล์แนบในไฟล์',
    collectAttachmentsInFiles: 'รวบรวมไฟล์แนบในหลายไฟล์'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'กำลังรวบรวมไฟล์แนบสำหรับ \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'การรวบรวมไฟล์แนบถูกยกเลิก ดูรายละเอียดในคอนโซล',
    generatedAttachmentFileNameIsInvalid: 'ชื่อไฟล์แนบที่สร้างขึ้น \'{{path}}\' ไม่ถูกต้อง\n{{validationMessage}}\nตรวจสอบการตั้งค่า {{settingName}} ของคุณ',
    notePathIsIgnored: 'เส้นทางโน้ตถูกข้าม'
  },
  obsidianLib: {
    buttons: {
      cancel: 'ยกเลิก',
      ok: 'ตกลง'
    },
    dataview: {
      itemsPerPage: 'รายการต่อหน้า:',
      jumpToPage: 'ไปที่หน้า:'
    },
    notices: {
      attachmentIsStillUsed: 'ไฟล์แนบ {{attachmentPath}} ยังคงถูกใช้โดยโน้ตอื่น ๆ จะไม่ถูกลบ',
      unhandledError: 'เกิดข้อผิดพลาดที่ไม่ได้รับการจัดการ กรุณาตรวจสอบคอนโซลสำหรับข้อมูลเพิ่มเติม'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'ไฟล์ทั้งหมดจะถูกเปลี่ยนชื่อ',
        displayText: 'ทั้งหมด'
      },
      none: {
        description: 'เก็บชื่อไฟล์เดิมไว้',
        displayText: 'ไม่มี'
      },
      onlyPastedImages: {
        description: 'เฉพาะภาพที่วางจะถูกเปลี่ยนชื่อ ใช้ได้เฉพาะเมื่อวางไฟล์ PNG จากคลิปบอร์ดโดยตรง โดยทั่วไปใช้สำหรับการวางภาพหน้าจอ',
        displayText: 'เฉพาะภาพที่วาง'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'ยกเลิกการรวบรวมไฟล์แนบ',
        displayText: 'ยกเลิก'
      },
      copy: {
        description: 'คัดลอกไฟล์แนบไปยังตำแหน่งใหม่',
        displayText: 'คัดลอก'
      },
      move: {
        description: 'ย้ายไฟล์แนบไปยังตำแหน่งใหม่',
        displayText: 'ย้าย'
      },
      prompt: {
        description: 'ให้ผู้ใช้เลือกการดำเนินการ',
        displayText: 'ถาม'
      },
      skip: {
        description: 'ข้ามไฟล์แนบและดำเนินการต่อไป',
        displayText: 'ข้าม'
      }
    },
    defaultImageSizeDimension: {
      height: 'ความสูง',
      width: 'ความกว้าง'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// โทเคนที่กำหนดเองถูกคอมเมนต์ไว้ เนื่องจากต้องอัปเดตเป็นรูปแบบใหม่ที่ถูกเพิ่มในปลั๊กอินเวอร์ชัน 9.0.0\n// ดูรายละเอียดในเอกสารประกอบ ({{customTokensDocumentationUrl}})',
      deprecated: 'รูปแบบการลงทะเบียนโทเคนที่กำหนดเองได้เปลี่ยนไป กรุณาอัปเดตโทเคนของคุณให้สอดคล้องกัน ดูข้อมูลเพิ่มเติมใน{{documentation}}'
    },
    legacyRenameAttachmentsToLowerCase: 'การตั้งค่า {{setting}} เลิกใช้แล้ว กรุณาใช้รูปแบบ {{format}} แทน ดูข้อมูลเพิ่มเติมใน{{documentation}}',
    markdownUrlFormat: {
      deprecated: 'ค่าที่คุณตั้งไว้สำหรับรูปแบบ {{setting}} อาจไม่ถูกต้อง กรุณาดูข้อมูลเพิ่มเติมใน{{documentation}} ข้อความนี้จะไม่แสดงอีก'
    },
    specialCharacters: 'ค่าเริ่มต้นของการตั้งค่า {{setting}} ถูกเปลี่ยนแล้ว ค่าการตั้งค่าของคุณถูกอัปเดตเป็นค่าเริ่มต้นใหม่',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'ขนาดภาพเริ่มต้นต้องเป็นพิกเซลหรือเปอร์เซ็นต์',
      invalidCustomTokensCode: 'โค้ดโทเคนที่กำหนดเองไม่ถูกต้อง',
      invalidRegularExpression: 'นิพจน์ปกติไม่ถูกต้อง {{regExp}}',
      specialCharactersMustNotContainSlash: 'อักขระพิเศษต้องไม่มีเครื่องหมาย /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'การแทนที่อักขระพิเศษต้องไม่มีอักขระที่ไม่ถูกต้องสำหรับชื่อไฟล์หรือเส้นทาง'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'เมื่อแนบไฟล์:',
      name: 'โหมดเปลี่ยนชื่อไฟล์แนบ'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'เมื่อไฟล์แนบที่รวบรวมถูกใช้โดยหลายโน้ต:',
      name: 'โหมดรวบรวมไฟล์แนบที่ใช้หลายโน้ต'
    },
    collectedAttachmentFileName: {
      description: 'ดู{{tokens}}ที่มีให้\nเว้นว่างไว้เพื่อคงชื่อไฟล์แนบปัจจุบัน',
      name: 'ชื่อไฟล์แนบที่รวบรวม'
    },
    customTokens: {
      description: 'โทเคนที่กำหนดเองที่จะใช้\nดูข้อมูลเพิ่มเติมใน{{documentation}}\n⚠️ โทเคนที่กำหนดเองสามารถเป็นโค้ด JavaScript ใดก็ได้ หากเขียนไม่ดีอาจทำให้ข้อมูลสูญหาย ใช้โดยยอมรับความเสี่ยงเอง',
      name: 'โทเคนที่กำหนดเอง'
    },
    defaultImageSize: {
      description: 'ขนาดภาพเริ่มต้น\nสามารถกำหนดเป็นพิกเซล ({{pixels}}) หรือเปอร์เซ็นต์ของขนาดภาพเต็ม ({{percentage}})\nเว้นว่างไว้เพื่อใช้ขนาดภาพต้นฉบับ',
      name: 'ขนาดภาพเริ่มต้น'
    },
    duplicateNameSeparator: {
      description: 'เมื่อคุณวางหรือลากไฟล์ที่มีชื่อเหมือนไฟล์ที่มีอยู่ ตัวคั่นนี้จะถูกเพิ่มลงในชื่อไฟล์\nเช่น เมื่อคุณลากไฟล์ {{existingFile}} ไฟล์จะถูกเปลี่ยนชื่อเป็น {{firstAvailableName}}, {{secondAvailableName}} เป็นต้น โดยใช้ชื่อแรกที่ว่าง',
      name: 'ตัวคั่นสำหรับชื่อซ้ำ'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'ยกเว้นไฟล์แนบจากเส้นทางต่อไปนี้เมื่อเรียกใช้คำสั่ง {{command}}\nใส่แต่ละเส้นทางในบรรทัดใหม่\n{{pathSyntax}}\nหากเว้นว่าง จะไม่มีเส้นทางใดถูกยกเว้นจากการรวบรวมไฟล์แนบ',
      name: 'ยกเว้นเส้นทางจากการรวบรวมไฟล์แนบ'
    },
    generatedAttachmentFileName: {
      description: 'ดู{{tokens}}ที่มีให้',
      name: 'ชื่อไฟล์แนบที่สร้างขึ้น'
    },
    jpegQuality: {
      description: 'คุณภาพยิ่งต่ำ อัตราส่วนการบีบอัดจะยิ่งสูง',
      name: 'คุณภาพ JPEG'
    },
    locationForNewAttachments: {
      description: 'ขึ้นต้นด้วย {{relativePrefix}} สำหรับเส้นทางที่สัมพันธ์กับโฟลเดอร์แม่ของโน้ต\nดู{{tokens}}ที่มีให้\nไม่แนะนำโฟลเดอร์ที่ขึ้นต้นด้วยจุด เช่น {{dotFolder}} เพราะ Obsidian ไม่ติดตามโฟลเดอร์เหล่านี้ คุณอาจต้องใช้ปลั๊กอิน {{unhidePlugin}} เพื่อจัดการ',
      name: 'ตำแหน่งไฟล์แนบใหม่'
    },
    markdownUrlFormat: {
      description: 'รูปแบบของ URL ที่จะแทรกลงใน Markdown เมื่อเพิ่มไฟล์แนบ ใช้เฉพาะในขณะนั้นเท่านั้น: ลิงก์ที่ Obsidian เขียนใหม่ภายหลัง เมื่อโน้ตหรือไฟล์แนบถูกเปลี่ยนชื่อหรือย้าย จะได้รูปแบบเริ่มต้น\nดู{{tokens}}ที่มีให้\nเว้นว่างไว้เพื่อใช้รูปแบบเริ่มต้น',
      name: 'รูปแบบ URL ของ Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'จะใช้การตั้งค่าโฟลเดอร์ไฟล์แนบและชื่อไฟล์กับไฟล์แนบที่ปลั๊กอินอื่นสร้างขึ้นหรือไม่\nปลั๊กอินบางตัวเขียนไฟล์แนบลงในห้องนิรภัยด้วยชื่อของตัวเอง โดยไม่ถาม Obsidian ว่าควรอยู่ที่ใด เมื่อเปิดตัวเลือกนี้ ไฟล์ดังกล่าวจะถูกย้ายและเปลี่ยนชื่อทันทีที่ปรากฏ\nจะแตะต้องเฉพาะไฟล์ที่สร้างขึ้นขณะเปิดโน้ตอยู่และมีโน้ตลิงก์ถึงเท่านั้น: ไฟล์ที่ไม่มีโน้ตใดลิงก์ถึงคือข้อมูลที่ปลั๊กอินอื่นเก็บไว้ใช้เอง และจะอยู่ที่เดิมที่ถูกเขียน ไฟล์ที่มาจากการซิงก์หรือการนำเข้าห้องนิรภัยจะไม่ถูกแตะต้องเลย\n{{modes}}\nปลั๊กอินที่สร้างไฟล์จะถูกระบุจาก call stack ของการเขียน ซึ่งทำได้ดีที่สุดเท่าที่ทำได้: จะไม่มีการระบุปลั๊กอินสำหรับไฟล์ที่เขียนโดย Obsidian เอง โดยไคลเอนต์ซิงก์ หรือโดยปลั๊กอินที่เลื่อนการเขียนออกไป ไฟล์ดังกล่าวถือว่าไม่อยู่ในรายการด้านล่าง',
      name: 'เปลี่ยนชื่อไฟล์แนบที่ปลั๊กอินอื่นสร้าง'
    },
    renameAttachmentsToLowerCase: 'เปลี่ยนชื่อไฟล์แนบเป็นตัวพิมพ์เล็ก',
    renamedAttachmentFileName: {
      description: 'ดู{{tokens}}ที่มีให้\nเว้นว่างไว้เพื่อคงชื่อไฟล์แนบปัจจุบัน',
      name: 'ชื่อไฟล์แนบที่เปลี่ยนชื่อ'
    },
    resetToSampleCustomTokens: {
      message: 'แน่ใจหรือไม่ว่าต้องการรีเซ็ตโทเคนที่กำหนดเองไปยังโทเคนตัวอย่าง? การเปลี่ยนแปลงทั้งหมดจะสูญหาย',
      title: 'รีเซ็ตเป็นโทเคนตัวอย่าง'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'กำหนดว่าจะเปลี่ยนรูปภาพที่วางเป็น JPEG หรือไม่ ใช้ได้กับ PNG ที่วางจากคลิปบอร์ดโดยตรง เหมาะสำหรับภาพหน้าจอ',
      name: 'แปลงรูปภาพที่วางเป็น JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'หากเปิดใช้งาน ไฟล์แนบที่ประมวลผลผ่านคำสั่ง {{command}} จะถูกเปลี่ยนชื่อตามการตั้งค่า {{setting}}',
      name: 'เปลี่ยนชื่อไฟล์แนบที่รวบรวมมา'
    },
    specialCharacters: {
      description: 'อักขระพิเศษในชื่อโฟลเดอร์และไฟล์แนบที่จะถูกแทนที่หรือเอาออก\nเว้นว่างไว้เพื่อเก็บอักขระพิเศษ',
      name: 'อักขระพิเศษ'
    },
    specialCharactersReplacement: {
      description: 'สตริงสำหรับแทนที่อักขระพิเศษในชื่อโฟลเดอร์และไฟล์แนบ\nเว้นว่างไว้เพื่อลบอักขระพิเศษ',
      name: 'ค่าที่แทนอักขระพิเศษ'
    },
    timeoutInSeconds: {
      description: 'เวลาจำกัด (วินาที) สำหรับทุกการดำเนินการ\nหากตั้งค่าเป็น {{zero}} เวลาจำกัดในการดำเนินการจะถูกปิดใช้งาน',
      name: 'เวลาจำกัดเป็นวินาที'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'เปลี่ยนชื่อไฟล์แนบ',
    folderTitle: 'เลือกโฟลเดอร์ไฟล์แนบ',
    previewModal: {
      title: 'ดูตัวอย่างไฟล์แนบ \'{{fullFileName}}\''
    },
    title: 'กรุณาใส่ค่าของโทเคนที่ร้องขอ'
  },
  regularExpression: '/นิพจน์ปกติ/'
};
