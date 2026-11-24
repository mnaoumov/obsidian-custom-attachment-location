export const id = {
  attachmentCollector: {
    confirm: 'Apakah Anda ingin mengumpulkan lampiran untuk semua catatan di folder berikut secara rekursif?\n{{folders}}\nOperasi ini tidak dapat dibatalkan.',
    progressBar: {
      message: 'Mengumpulkan lampiran {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Mengumpulkan lampiran...'
    }
  },
  buttons: {
    copy: 'Salin',
    move: 'Pindah',
    previewAttachmentFile: 'Pratinjau file lampiran',
    skip: 'Lewati'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'Lampiran {{attachment}} dirujuk oleh beberapa catatan.',
    heading: 'Mengumpulkan lampiran yang digunakan oleh beberapa catatan',
    noPriorityWinnerReason: {
      EmptyList: 'Lampiran tidak dipindahkan karena pengaturan {{settingName}} kosong, sehingga tidak ada yang menentukan catatan mana yang memilikinya.',
      NoMatch: 'Lampiran tidak dipindahkan karena tidak ada catatan ini yang cocok dengan entri mana pun di pengaturan {{settingName}}.',
      Tie: 'Lampiran tidak dipindahkan karena beberapa catatan ini sama-sama cocok dengan pengaturan {{settingName}}, sehingga tidak menunjuk satu pemilik.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Harus menggunakan tindakan yang sama untuk lampiran bermasalah lainnya'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Kumpulkan lampiran di folder saat ini',
    collectAttachmentsCurrentNote: 'Kumpulkan lampiran di catatan saat ini',
    collectAttachmentsEntireVault: 'Kumpulkan lampiran di seluruh vault'
  },
  links: {
    documentation: 'dokumentasi',
    tokens: 'token'
  },
  menuItems: {
    collectAttachmentsInFile: 'Kumpulkan lampiran di file',
    collectAttachmentsInFiles: 'Kumpulkan lampiran di file-file'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Mengumpulkan lampiran untuk \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Pengumpulan lampiran dibatalkan. Lihat konsol untuk detail.',
    generatedAttachmentFileNameIsInvalid: 'Nama file lampiran yang dihasilkan \'{{path}}\' tidak valid.\n{{validationMessage}}\nPeriksa pengaturan {{settingName}} Anda.',
    notePathIsIgnored: 'Jalur catatan diabaikan'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Batal',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Item per halaman:',
      jumpToPage: 'Lompat ke halaman:'
    },
    notices: {
      attachmentIsStillUsed: 'Lampiran {{attachmentPath}} masih digunakan oleh catatan lain. Tidak akan dihapus.',
      unhandledError: 'Terjadi kesalahan yang tidak tertangani. Silakan periksa konsol untuk informasi lebih lanjut.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'semua file akan diubah namanya.',
        displayText: 'Semua'
      },
      none: {
        description: 'nama mereka dipertahankan.',
        displayText: 'Tidak ada'
      },
      onlyPastedImages: {
        description: 'hanya gambar yang ditempel yang akan diubah namanya. Berlaku hanya ketika konten gambar PNG ditempel langsung dari clipboard. Biasanya, untuk menempel screenshot.',
        displayText: 'Hanya gambar yang ditempel'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'batalkan pengumpulan lampiran.',
        displayText: 'Batal'
      },
      copy: {
        description: 'salin lampiran ke lokasi baru.',
        displayText: 'Salin'
      },
      move: {
        description: 'pindahkan lampiran ke lokasi baru.',
        displayText: 'Pindah'
      },
      prompt: {
        description: 'minta pengguna untuk memilih tindakan.',
        displayText: 'Permintaan'
      },
      skip: {
        description: 'lewati lampiran dan lanjutkan ke yang berikutnya.',
        displayText: 'Lewati'
      }
    },
    defaultImageSizeDimension: {
      height: 'Tinggi',
      width: 'Lebar'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Token kustom dikomentari karena harus diperbarui ke format baru yang diperkenalkan di versi plugin 9.0.0.\n// Lihat dokumentasi ({{customTokensDocumentationUrl}}) untuk informasi lebih lanjut.',
      deprecated: 'Format registrasi token kustom telah berubah. Silakan perbarui token Anda sesuai dengan format baru. Lihat {{documentation}} untuk informasi lebih lanjut.'
    },
    legacyRenameAttachmentsToLowerCase: 'Pengaturan {{setting}} sudah tidak digunakan lagi. Gunakan format {{format}} sebagai gantinya. Lihat {{documentation}} untuk informasi lebih lanjut.',
    markdownUrlFormat: {
      deprecated: 'Anda mungkin memiliki nilai yang salah untuk format {{setting}}. Silakan lihat {{documentation}} untuk informasi lebih lanjut. Pesan ini tidak akan ditampilkan lagi.'
    },
    specialCharacters: 'Nilai default pengaturan {{setting}} telah berubah. Nilai pengaturan Anda diperbarui ke nilai default yang baru.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Ukuran gambar default harus dalam piksel atau persentase',
      invalidCustomTokensCode: 'Kode token kustom tidak valid',
      invalidRegularExpression: 'Ekspresi reguler tidak valid {{regExp}}',
      specialCharactersMustNotContainSlash: 'Karakter khusus tidak boleh mengandung /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Penggantian karakter khusus tidak boleh mengandung karakter jalur nama file yang tidak valid.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Saat melampirkan file:',
      name: 'Mode penggantian nama lampiran'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Ketika lampiran yang dikumpulkan digunakan oleh beberapa catatan:',
      name: 'Mode pengumpulan lampiran yang digunakan oleh beberapa catatan'
    },
    collectedAttachmentFileName: {
      description: 'Lihat {{tokens}} yang tersedia.\nBiarkan kosong untuk mempertahankan nama file lampiran saat ini.',
      name: 'Nama file lampiran yang dikumpulkan'
    },
    customTokens: {
      description: 'Token kustom yang akan digunakan.\nLihat {{documentation}} untuk informasi lebih lanjut.\n⚠️ Token kustom dapat berupa kode JavaScript arbitrer. Jika ditulis dengan buruk, dapat menyebabkan kehilangan data. Gunakan dengan risiko sendiri.',
      name: 'Token kustom'
    },
    defaultImageSize: {
      description: 'Ukuran gambar default.\nDapat ditentukan dalam piksel ({{pixels}}) atau persentase dari ukuran gambar penuh ({{percentage}}).\nBiarkan kosong untuk menggunakan ukuran gambar asli.',
      name: 'Default image size'
    },
    duplicateNameSeparator: {
      description: 'Ketika Anda menempel atau menyeret file dengan nama yang sama dengan file yang sudah ada, pemisah ini akan ditambahkan ke nama file.\nMisalnya, ketika Anda menyeret file {{existingFile}}, file itu akan diubah namanya menjadi {{firstAvailableName}}, {{secondAvailableName}}, dan seterusnya, sesuai nama pertama yang tersedia.',
      name: 'Pemisah nama duplikat'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Kecualikan lampiran dari jalur berikut ketika perintah {{command}} dijalankan.\nMasukkan setiap jalur pada baris baru.\n{{pathSyntax}}\nJika pengaturan kosong, tidak ada jalur yang dikecualikan dari pengumpulan lampiran.',
      name: 'Kecualikan jalur dari pengumpulan lampiran'
    },
    generatedAttachmentFileName: {
      description: 'Lihat {{tokens}} yang tersedia.',
      name: 'Nama file lampiran yang dihasilkan'
    },
    jpegQuality: {
      description: 'Semakin kecil kualitasnya, semakin besar rasio kompresi.',
      name: 'Kualitas JPEG'
    },
    locationForNewAttachments: {
      description: 'Mulai dengan {{relativePrefix}} untuk jalur yang relatif terhadap folder induk catatan.\nLihat {{tokens}} yang tersedia.\nFolder titik seperti {{dotFolder}} tidak direkomendasikan, karena Obsidian tidak melacaknya. Anda mungkin perlu menggunakan plugin {{unhidePlugin}} untuk mengelolanya.',
      name: 'Lokasi untuk lampiran baru'
    },
    markdownUrlFormat: {
      description: 'Format untuk URL yang akan dimasukkan ke Markdown saat lampiran ditambahkan. Format ini hanya diterapkan pada saat itu: tautan yang ditulis ulang oleh Obsidian kemudian, saat catatan atau lampiran diubah namanya atau dipindahkan, mendapatkan format default.\nLihat {{tokens}} yang tersedia.\nBiarkan kosong untuk menggunakan format default.',
      name: 'Format URL Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Apakah pengaturan folder lampiran dan nama berkas diterapkan pada lampiran yang dibuat plugin LAIN.\nSebagian plugin menulis lampiran langsung ke vault dengan nama pilihannya sendiri, tanpa menanyakan Obsidian di mana tempatnya. Bila ini diaktifkan, berkas seperti itu dipindahkan dan diganti namanya begitu muncul.\nHanya berkas yang dibuat saat sebuah catatan terbuka, dan ditautkan dari sebuah catatan, yang disentuh: berkas yang tidak ditautkan oleh catatan mana pun adalah data yang disimpan plugin lain untuk dirinya sendiri dan tetap berada di tempat ia ditulis. Berkas yang datang dari sinkronisasi atau impor vault tidak pernah disentuh.\n{{modes}}\nPlugin pembuat dikenali dari call stack penulisan. Ini hanya upaya terbaik: tidak ada plugin yang dikenali untuk berkas yang ditulis oleh Obsidian sendiri, oleh klien sinkronisasi, atau oleh plugin yang menunda penulisannya. Berkas seperti itu dianggap TIDAK ada dalam daftar di bawah.',
      name: 'Ganti nama lampiran yang dibuat plugin lain'
    },
    renameAttachmentsToLowerCase: 'Ubah nama lampiran menjadi huruf kecil',
    renamedAttachmentFileName: {
      description: 'Lihat {{tokens}} yang tersedia.\nBiarkan kosong untuk mempertahankan nama file lampiran saat ini.',
      name: 'Nama file lampiran yang diubah namanya'
    },
    resetToSampleCustomTokens: {
      message: 'Apakah Anda yakin ingin mengatur ulang token kustom ke token kustom sampel? Perubahan Anda akan hilang.',
      title: 'Atur ulang ke token kustom sampel'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Apakah akan mengkonversi gambar yang ditempel ke JPEG. Berlaku hanya ketika konten gambar PNG ditempel langsung dari clipboard. Biasanya, untuk menempel screenshot.',
      name: 'Haruskah mengkonversi gambar yang ditempel ke JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Jika diaktifkan, lampiran yang diproses melalui perintah {{command}} akan diubah namanya sesuai dengan pengaturan {{setting}}.',
      name: 'Haruskah mengubah nama lampiran yang dikumpulkan'
    },
    specialCharacters: {
      description: 'Karakter khusus dalam nama folder dan nama file lampiran yang akan diganti atau dihapus.\nBiarkan kosong untuk mempertahankan karakter khusus.',
      name: 'Karakter khusus'
    },
    specialCharactersReplacement: {
      description: 'String pengganti untuk karakter khusus dalam nama folder dan nama file lampiran.\nBiarkan kosong untuk menghapus karakter khusus.',
      name: 'Penggantian karakter khusus'
    },
    timeoutInSeconds: {
      description: 'Timeout dalam detik untuk semua operasi.\nJika diatur ke {{zero}}, timeout eksekusi operasi dinonaktifkan.',
      name: 'Timeout dalam detik'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Ganti nama file lampiran',
    folderTitle: 'Pilih folder lampiran',
    previewModal: {
      title: 'Pratinjau file lampiran \'{{fullFileName}}\''
    },
    title: 'Berikan nilai untuk token prompt'
  },
  regularExpression: '/ekspresi reguler/'
};
